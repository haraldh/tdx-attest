/*
* Copyright (c) 2023, Intel Corporation. All rights reserved.<BR>
* SPDX-License-Identifier: Apache-2.0
*/

#![allow(non_camel_case_types)]

use anyhow::{anyhow, bail, Context, Result};
use std::fs::File;
use std::mem;
use std::os::unix::io::AsRawFd;
use std::ptr;

#[repr(C)]
pub struct TdxReportRequest {
    reportdata: [u8; REPORT_DATA_LEN], // User buffer with REPORTDATA to be included into TDREPORT
    tdreport: [u8; TDX_REPORT_LEN], // User buffer to store TDREPORT output from TDCALL[TDG.MR.REPORT]
}

pub enum TdxVersion {
    TDX_1_0,
    TDX_1_5,
}

pub enum TdxOperation {
    TDX_GET_TD_REPORT = 1,
    TDX_1_0_GET_QUOTE = 2,
    TDX_1_5_GET_QUOTE = 4,
}

const REPORT_DATA_LEN: usize = 64;
const TDX_REPORT_LEN: usize = 1024;
const TDX_QUOTE_LEN: usize = 4 * 4096;

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum TeeType {
    SGX = 0x00,
    TDX = 0x81,
}

/// REPORTTYPE indicates the reported Trusted Execution Environment (TEE) type,
/// sub-type and version.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ReportType {
    /// Trusted Execution Environment (TEE) Type. 0x00: SGX, 0x81: TDX.
    pub tee_type: TeeType,
    /// TYPE-specific subtype.
    pub sub_type: u8,
    /// TYPE-specific version.
    pub version: u8,
    pub reserved: u8,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ReportMac {
    /// Type Header Structure.
    pub report_type: ReportType,
    pub reserved_1: [u8; 12],
    pub cpu_svn: [u8; 16],
    /// SHA384 of TEE_TCB_INFO for TEEs implemented using Intel TDX.
    pub tee_tcb_info_hash: [u8; 48],
    /// SHA384 of TEE_INFO: a TEE-specific info structure (TDINFO_STRUCT or SGXINFO)
    /// or 0 if no TEE is represented.
    pub tee_info_hash: [u8; 48],
    /// A set of data used for communication between the caller and the target.
    pub report_data: [u8; 64],
    pub reserved_2: [u8; 32],
    /// The MAC over the REPORTMACSTRUCT with model-specific MAC.
    pub mac: [u8; 32],
}

/// TDINFO_STRUCT is defined as the TDX-specific TEE_INFO part of TDG.MR.REPORT.
/// It contains the measurements and initial configuration of the TD that was
/// locked at initialization and a set of measurement registers that are run-time
/// extendable. These values are copied from the TDCS by the TDG.MR.REPORT function.
/// Refer to the [TDX Module Base Spec] for additional details.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct TdInfo {
    /// TD’s ATTRIBUTES.
    pub attributes: u64,
    /// TD’s XFAM.
    pub xfam: u64,
    /// Measurement of the initial contents of the TD.
    pub mrtd: [u8; 48],
    /// Software-defined ID for non-owner-defined configuration of the
    /// guest TD – e.g., run-time or OS configuration.
    pub mr_config_id: [u8; 48],
    /// Software-defined ID for the guest TD’s owner.
    pub mr_owner: [u8; 48],
    /// Software-defined ID for owner-defined configuration of the
    /// guest TD – e.g., specific to the workload rather than the run-time or OS.
    pub mr_owner_config: [u8; 48],
    /// Array of NUM_RTMRS (4) run-time extendable measurement registers.
    pub rtmr0: [u8; 48],
    pub rtmr1: [u8; 48],
    pub rtmr2: [u8; 48],
    pub rtmr3: [u8; 48],
    /// If is one or more bound or pre-bound service TDs, SERVTD_HASH is the SHA384 hash of the
    /// TDINFO_STRUCTs of those service TDs bound. Else, SERVTD_HASH is 0.
    pub servtd_hash: [u8; 48],
    pub reserved: [u8; 64],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct TdReport {
    /// REPORTMACSTRUCT for the TDG.MR.REPORT.
    pub report_mac: ReportMac,
    /// Additional attestable elements in the TD’s TCB are not reflected in the
    /// REPORTMACSTRUCT.CPUSVN – includes the Intel TDX module measurements.
    pub tee_tcb_info: [u8; 239],
    pub reserved: [u8; 17],
    /// TD’s attestable properties.
    pub tdinfo: TdInfo,
}
const _: () = assert!(TDX_REPORT_LEN == size_of::<TdReport>());

fn get_tdx_1_5_report(
    device_node: &mut File,
    report_data_bytes: &[u8; REPORT_DATA_LEN],
) -> Result<Vec<u8>> {
    //prepare get TDX report request data
    let mut request = TdxReportRequest {
        reportdata: [0; REPORT_DATA_LEN],
        tdreport: [0; TDX_REPORT_LEN],
    };
    request.reportdata.copy_from_slice(report_data_bytes);

    //build the operator code
    nix::ioctl_readwrite!(
        get_report_1_5_ioctl,
        b'T',
        TdxOperation::TDX_GET_TD_REPORT,
        TdxReportRequest
    );

    //apply the ioctl command
    if let Err(e) = unsafe {
        get_report_1_5_ioctl(
            device_node.as_raw_fd(),
            ptr::addr_of!(request) as *mut TdxReportRequest,
        )
    } {
        bail!("[get_tdx_1_5_report] Failed to get TDX report: {:?}", e)
    };

    Ok(request.tdreport.to_vec())
}

#[repr(C)]
pub struct qgs_msg_header {
    major_version: u16, // TDX major version
    minor_version: u16, // TDX minor version
    msg_type: u32,      // GET_QUOTE_REQ or GET_QUOTE_RESP
    size: u32,          // size of the whole message, include this header, in byte
    error_code: u32,    // used in response only
}

#[repr(C)]
pub struct qgs_msg_get_quote_req {
    header: qgs_msg_header,               // header.type = GET_QUOTE_REQ
    report_size: u32,                     // cannot be 0
    id_list_size: u32,                    // length of id_list, in byte, can be 0
    report_id_list: [u8; TDX_REPORT_LEN], // report followed by id list
}

#[repr(C)]
pub struct tdx_quote_hdr {
    version: u64,               // Quote version, filled by TD
    status: u64,                // Status code of Quote request, filled by VMM
    in_len: u32,                // Length of TDREPORT, filled by TD
    out_len: u32,               // Length of Quote, filled by VMM
    data_len_be_bytes: [u8; 4], // big-endian 4 bytes indicate the size of data following
    data: [u8; TDX_QUOTE_LEN],  // Actual Quote data or TDREPORT on input
}

#[repr(C)]
pub struct tdx_quote_req {
    buf: u64, // Pass user data that includes TDREPORT as input. Upon successful completion of IOCTL, output is copied back to the same buffer
    len: u64, // Length of the Quote buffer
}

#[repr(C)]
pub struct qgs_msg_get_quote_resp {
    header: qgs_msg_header,        // header.type = GET_QUOTE_RESP
    selected_id_size: u32,         // can be 0 in case only one id is sent in request
    quote_size: u32,               // length of quote_data, in byte
    id_quote: [u8; TDX_QUOTE_LEN], // selected id followed by quote
}
fn generate_qgs_quote_msg(report: [u8; TDX_REPORT_LEN]) -> qgs_msg_get_quote_req {
    //build quote service message header to be used by QGS
    let qgs_header = qgs_msg_header {
        major_version: 1,
        minor_version: 0,
        msg_type: 0,
        size: (16 + 8 + TDX_REPORT_LEN) as u32, // header + report_size and id_list_size + TDX_REPORT_LEN
        error_code: 0,
    };

    //build quote service message body to be used by QGS
    let mut qgs_request = qgs_msg_get_quote_req {
        header: qgs_header,
        report_size: TDX_REPORT_LEN as u32,
        id_list_size: 0,
        report_id_list: [0; TDX_REPORT_LEN],
    };

    qgs_request.report_id_list.copy_from_slice(&report[0..]);

    qgs_request
}
pub fn get_tdx_quote(report_data_bytes: &[u8; REPORT_DATA_LEN]) -> Result<Vec<u8>, anyhow::Error> {
    let mut device_node = File::options()
        .read(true)
        .write(true)
        .open("/dev/tdx_guest")
        .context("opening /dev/tdx_guest failed")?;

    //retrive TDX report
    let report_data_vec = match get_tdx_1_5_report(&mut device_node, report_data_bytes) {
        Err(e) => return Err(anyhow!("[get_tdx_quote] Fail to get TDX report: {:?}", e)),
        Ok(report) => report,
    };
    let report_data_array: [u8; TDX_REPORT_LEN as usize] = match report_data_vec.try_into() {
        Ok(r) => r,
        Err(e) => return Err(anyhow!("[get_tdx_quote] Wrong TDX report format: {:?}", e)),
    };

    //build QGS request message
    let qgs_msg = generate_qgs_quote_msg(report_data_array);

    //build quote generation request header
    let mut quote_header = tdx_quote_hdr {
        version: 1,
        status: 0,
        in_len: (mem::size_of_val(&qgs_msg) + 4) as u32,
        out_len: 0,
        data_len_be_bytes: (1048 as u32).to_be_bytes(),
        data: [0; TDX_QUOTE_LEN as usize],
    };

    let qgs_msg_bytes = unsafe {
        let ptr = &qgs_msg as *const qgs_msg_get_quote_req as *const u8;
        std::slice::from_raw_parts(ptr, mem::size_of::<qgs_msg_get_quote_req>())
    };
    quote_header.data[0..(16 + 8 + TDX_REPORT_LEN) as usize]
        .copy_from_slice(&qgs_msg_bytes[0..((16 + 8 + TDX_REPORT_LEN) as usize)]);

    let request = tdx_quote_req {
        buf: ptr::addr_of!(quote_header) as u64,
        len: TDX_QUOTE_LEN as u64,
    };

    nix::ioctl_read!(
        get_quote_1_5_ioctl,
        b'T',
        TdxOperation::TDX_1_5_GET_QUOTE,
        tdx_quote_req
    );
    match unsafe {
        get_quote_1_5_ioctl(
            device_node.as_raw_fd(),
            ptr::addr_of!(request) as *mut tdx_quote_req,
        )
    } {
        Err(e) => return Err(anyhow!("[get_tdx_quote] Fail to get TDX quote: {:?}", e)),
        Ok(_r) => _r,
    };

    //inspect the response and retrive quote data
    let out_len = quote_header.out_len;
    let qgs_msg_resp_size =
        unsafe { std::mem::transmute::<[u8; 4], u32>(quote_header.data_len_be_bytes) }.to_be();

    let qgs_msg_resp = unsafe {
        let raw_ptr = ptr::addr_of!(quote_header.data) as *mut qgs_msg_get_quote_resp;
        raw_ptr.as_mut().unwrap() as &mut qgs_msg_get_quote_resp
    };

    if out_len - qgs_msg_resp_size != 4 {
        return Err(anyhow!(
            "[get_tdx_quote] Fail to get TDX quote: wrong TDX quote size!"
        ));
    }

    if qgs_msg_resp.header.major_version != 1
        || qgs_msg_resp.header.minor_version != 0
        || qgs_msg_resp.header.msg_type != 1
        || qgs_msg_resp.header.error_code != 0
    {
        return Err(anyhow!(
            "[get_tdx_quote] Fail to get TDX quote: QGS response error!"
        ));
    }

    Ok(qgs_msg_resp.id_quote[0..(qgs_msg_resp.quote_size as usize)].to_vec())
}

pub fn main() -> Result<()> {
    let report_data_bytes: [u8; REPORT_DATA_LEN] = [0xee; REPORT_DATA_LEN];

    let report = get_tdx_quote(&report_data_bytes)?;
    println!("TDX Report: {:?}", report);
    Ok(())
}
