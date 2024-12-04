/*
* Copyright (c) 2023, Intel Corporation. All rights reserved.<BR>
* SPDX-License-Identifier: Apache-2.0
*/

#![allow(non_camel_case_types)]

use anyhow::{bail, Context, Result};
use std::fs::File;
use std::mem::MaybeUninit;
use std::os::unix::io::AsRawFd;
use std::ptr;
use std::ptr::slice_from_raw_parts_mut;

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

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum TeeType {
    SGX,
    TDX,
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
    pub cpu_svn: [u8; 16],
    /// SHA384 of TEE_TCB_INFO for TEEs implemented using Intel TDX.
    pub tee_tcb_info_hash: [u8; 48],
    /// SHA384 of TEE_INFO: a TEE-specific info structure (TDINFO_STRUCT or SGXINFO)
    /// or 0 if no TEE is represented.
    pub tee_info_hash: [u8; 48],
    /// A set of data used for communication between the caller and the target.
    pub report_data: [u8; 64],
    pub reserved: [u8; 32],
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

fn get_tdx_1_5_report(
    device_node: File,
    report_data_bytes: &[u8; REPORT_DATA_LEN],
) -> Result<TdReport> {
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

    const _: () = assert!(TDX_REPORT_LEN >= size_of::<TdReport>());

    let mut td_report_buf = MaybeUninit::<TdReport>::uninit();
    let td_report = unsafe {
        let buf =
            slice_from_raw_parts_mut(td_report_buf.as_mut_ptr() as *mut u8, size_of::<TdReport>());
        (*buf).copy_from_slice(&request.tdreport[..size_of::<TdReport>()]);
        td_report_buf.assume_init()
    };

    Ok(td_report)
}

pub fn main() -> Result<()> {
    let device_node = File::options()
        .read(true)
        .write(true)
        .open("/dev/tdx_guest")
        .context("opening /dev/tdx_guest failed")?;

    let report_data_bytes: [u8; REPORT_DATA_LEN] = [0xee; REPORT_DATA_LEN];

    let report = get_tdx_1_5_report(device_node, &report_data_bytes)?;
    println!("TDX Report: {:?}", report);
    Ok(())
}
