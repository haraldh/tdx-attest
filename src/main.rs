use anyhow::{bail, Result};
use tdx_attest_rs::*;

pub fn main() -> Result<()> {
    let tdx_report_data = tdx_report_data_t { d: [0; 64usize] };
    let att_key_id_list = [tdx_uuid_t { d: [0; 16usize] }; 2usize];
    //let list_size = 1024;
    let mut att_key_id = tdx_uuid_t { d: [0; 16usize] };
    let (error, quote) = tdx_att_get_quote(
        Some(&tdx_report_data),
        Some(&att_key_id_list),
        Some(&mut att_key_id),
        0,
    );

    if error == tdx_attest_error_t::TDX_ATTEST_SUCCESS {
        if let Some(quote) = quote {
            println!("bytes memory sampleQuote = hex\"{}\";", hex::encode(&quote));
        } else {
            bail!("tdx_att_get_quote: No quote returned");
        }
    } else {
        bail!("tdx_att_get_quote: {error:?}");
    }

    Ok(())
}
