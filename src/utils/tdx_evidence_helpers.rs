use anyhow::{anyhow, bail, Context, Result};
use core::fmt;
use log::debug;
use serde_json::{Map, Value};
pub type TeeEvidenceParsedClaim = serde_json::Value;
use az_tdx_vtpm::vtpm::Quote as TpmQuote;
use scroll::Pread;
use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};
use log::warn;
use byteorder::{LittleEndian, ReadBytesExt};
use strum::AsRefStr;
use std::str::FromStr;
use sha2::{digest::FixedOutput, Digest, Sha256, Sha384, Sha512};

use eventlog_rs::Eventlog;

/// Takes in tdx_evidence as a vec<u8>, as it is returned by coco libs,
/// and prints out the claim as a string
pub fn get_tdx_evidence_claims(tdx_evidence: Vec<u8>) -> Result<(), anyhow::Error> {
    let evidence = serde_json::from_slice::<Evidence>(tdx_evidence.as_slice())
        .context("Failed to deserialize Azure vTPM TDX evidence")?;
    let td_quote = parse_tdx_quote(&evidence.td_quote)?;
    let mut claim = generate_parsed_claim(td_quote)?;
    extend_claim_with_tpm_quote(&mut claim, &evidence.tpm_quote)?;
    let claim = serde_json::to_string_pretty(&claim)?;
    println!("{claim}");
    Ok(())
}

macro_rules! parse_claim {
    ($map_name: ident, $key_name: literal, $field: ident) => {
        $map_name.insert($key_name.to_string(), serde_json::Value::Object($field))
    };
    ($map_name: ident, $key_name: literal, $field: expr) => {
        $map_name.insert(
            $key_name.to_string(),
            serde_json::Value::String(hex::encode($field)),
        )
    };
}

#[derive(Serialize, Deserialize)]
pub struct Evidence {
    pub tpm_quote: TpmQuote,
    pub hcl_report: Vec<u8>,
    pub td_quote: Vec<u8>,
}

pub fn generate_parsed_claim(
    quote: Quote,
    cc_eventlog: Option<CcEventLog>,
    aa_eventlog: Option<AAEventlog>,
) -> Result<TeeEvidenceParsedClaim> {
    let mut quote_map = Map::new();
    let mut quote_body = Map::new();
    let mut quote_header = Map::new();

    match &quote {
        Quote::V4 { header, body } => {
            parse_claim!(quote_header, "version", b"\x04\x00");
            parse_claim!(quote_header, "att_key_type", header.att_key_type);
            parse_claim!(quote_header, "tee_type", header.tee_type);
            parse_claim!(quote_header, "reserved", header.reserved);
            parse_claim!(quote_header, "vendor_id", header.vendor_id);
            parse_claim!(quote_header, "user_data", header.user_data);
            parse_claim!(quote_body, "tcb_svn", body.tcb_svn);
            parse_claim!(quote_body, "mr_seam", body.mr_seam);
            parse_claim!(quote_body, "mrsigner_seam", body.mrsigner_seam);
            parse_claim!(quote_body, "seam_attributes", body.seam_attributes);
            parse_claim!(quote_body, "td_attributes", body.td_attributes);
            parse_claim!(quote_body, "xfam", body.xfam);
            parse_claim!(quote_body, "mr_td", body.mr_td);
            parse_claim!(quote_body, "mr_config_id", body.mr_config_id);
            parse_claim!(quote_body, "mr_owner", body.mr_owner);
            parse_claim!(quote_body, "mr_owner_config", body.mr_owner_config);
            parse_claim!(quote_body, "rtmr_0", body.rtmr_0);
            parse_claim!(quote_body, "rtmr_1", body.rtmr_1);
            parse_claim!(quote_body, "rtmr_2", body.rtmr_2);
            parse_claim!(quote_body, "rtmr_3", body.rtmr_3);
            parse_claim!(quote_body, "report_data", body.report_data);

            parse_claim!(quote_map, "header", quote_header);
            parse_claim!(quote_map, "body", quote_body);
        }
        Quote::V5 {
            header,
            r#type,
            size,
            body,
        } => {
            parse_claim!(quote_header, "version", b"\x05\x00");
            parse_claim!(quote_header, "att_key_type", header.att_key_type);
            parse_claim!(quote_header, "tee_type", header.tee_type);
            parse_claim!(quote_header, "reserved", header.reserved);
            parse_claim!(quote_header, "vendor_id", header.vendor_id);
            parse_claim!(quote_header, "user_data", header.user_data);
            parse_claim!(quote_map, "type", r#type.as_bytes());
            parse_claim!(quote_map, "size", &size[..]);
            match body {
                QuoteV5Body::Tdx10(body) => {
                    parse_claim!(quote_body, "tcb_svn", body.tcb_svn);
                    parse_claim!(quote_body, "mr_seam", body.mr_seam);
                    parse_claim!(quote_body, "mrsigner_seam", body.mrsigner_seam);
                    parse_claim!(quote_body, "seam_attributes", body.seam_attributes);
                    parse_claim!(quote_body, "td_attributes", body.td_attributes);
                    parse_claim!(quote_body, "xfam", body.xfam);
                    parse_claim!(quote_body, "mr_td", body.mr_td);
                    parse_claim!(quote_body, "mr_config_id", body.mr_config_id);
                    parse_claim!(quote_body, "mr_owner", body.mr_owner);
                    parse_claim!(quote_body, "mr_owner_config", body.mr_owner_config);
                    parse_claim!(quote_body, "rtmr_0", body.rtmr_0);
                    parse_claim!(quote_body, "rtmr_1", body.rtmr_1);
                    parse_claim!(quote_body, "rtmr_2", body.rtmr_2);
                    parse_claim!(quote_body, "rtmr_3", body.rtmr_3);
                    parse_claim!(quote_body, "report_data", body.report_data);

                    parse_claim!(quote_map, "header", quote_header);
                    parse_claim!(quote_map, "body", quote_body);
                }
                QuoteV5Body::Tdx15(body) => {
                    parse_claim!(quote_body, "tcb_svn", body.tcb_svn);
                    parse_claim!(quote_body, "mr_seam", body.mr_seam);
                    parse_claim!(quote_body, "mrsigner_seam", body.mrsigner_seam);
                    parse_claim!(quote_body, "seam_attributes", body.seam_attributes);
                    parse_claim!(quote_body, "td_attributes", body.td_attributes);
                    parse_claim!(quote_body, "xfam", body.xfam);
                    parse_claim!(quote_body, "mr_td", body.mr_td);
                    parse_claim!(quote_body, "mr_config_id", body.mr_config_id);
                    parse_claim!(quote_body, "mr_owner", body.mr_owner);
                    parse_claim!(quote_body, "mr_owner_config", body.mr_owner_config);
                    parse_claim!(quote_body, "rtmr_0", body.rtmr_0);
                    parse_claim!(quote_body, "rtmr_1", body.rtmr_1);
                    parse_claim!(quote_body, "rtmr_2", body.rtmr_2);
                    parse_claim!(quote_body, "rtmr_3", body.rtmr_3);
                    parse_claim!(quote_body, "report_data", body.report_data);

                    parse_claim!(quote_body, "tee_tcb_svn2", body.tee_tcb_svn2);
                    parse_claim!(quote_body, "mr_servicetd", body.mr_servicetd);
                    parse_claim!(quote_map, "header", quote_header);
                    parse_claim!(quote_map, "body", quote_body);
                }
            }
        }
    }

    // Claims from CC EventLog.
    let mut ccel_map = Map::new();
    if let Some(ccel) = cc_eventlog {
        parse_ccel(ccel, &mut ccel_map)?;
    }

    let mut claims = Map::new();

    // Claims from AA eventlog
    if let Some(aael) = aa_eventlog {
        let aael_map = aael.to_parsed_claims();
        parse_claim!(claims, "aael", aael_map);
    }

    parse_claim!(claims, "quote", quote_map);
    parse_claim!(claims, "ccel", ccel_map);

    parse_claim!(claims, "report_data", quote.report_data());
    parse_claim!(claims, "init_data", quote.mr_config_id());

    let claims_str = serde_json::to_string_pretty(&claims)?;
    debug!("Parsed Evidence claims map: \n{claims_str}\n");

    Ok(Value::Object(claims) as TeeEvidenceParsedClaim)
}

fn parse_ccel(ccel: CcEventLog, ccel_map: &mut Map<String, Value>) -> Result<()> {
    // Digest of kernel using td-shim
    match ccel.query_digest(MeasuredEntity::TdShimKernel) {
        Some(kernel_digest) => {
            ccel_map.insert(
                "kernel".to_string(),
                serde_json::Value::String(kernel_digest),
            );
        }
        _ => {
            warn!("No td-shim kernel hash in CCEL");
        }
    }

    // Digest of kernel using TDVF
    match ccel.query_digest(MeasuredEntity::TdvfKernel) {
        Some(kernel_digest) => {
            ccel_map.insert(
                "kernel".to_string(),
                serde_json::Value::String(kernel_digest),
            );
        }
        _ => {
            warn!("No tdvf kernel hash in CCEL");
        }
    }

    // Map of Kernel Parameters
    match ccel.query_event_data(MeasuredEntity::TdShimKernelParams) {
        Some(config_info) => {
            let td_shim_platform_config_info =
                TdShimPlatformConfigInfo::try_from(&config_info[..]).expect("ccel parsing fail in tdx_utils");

            let parameters = parse_kernel_parameters(td_shim_platform_config_info.data)?;
            ccel_map.insert(
                "kernel_parameters".to_string(),
                serde_json::Value::Object(parameters),
            );
        }
        _ => {
            warn!("No kernel parameters in CCEL");
        }
    }

    Ok(())
}

type Descriptor = [u8; 16];
type InfoLength = u32;
/// Kernel Commandline Event inside Eventlog
#[derive(Debug, PartialEq)]
pub struct TdShimPlatformConfigInfo<'a> {
    pub descriptor: Descriptor,
    pub info_length: InfoLength,
    pub data: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for TdShimPlatformConfigInfo<'a> {
    type Error = PlatformConfigInfoError;

    fn try_from(data: &'a [u8]) -> std::result::Result<Self, Self::Error> {
        let descriptor_size = core::mem::size_of::<Descriptor>();

        let info_size = core::mem::size_of::<InfoLength>();

        let header_size = descriptor_size + info_size;

        if data.len() < header_size {
            return Err(PlatformConfigInfoError::InvalidHeader);
        }

        let descriptor = data[0..descriptor_size]
            .try_into()
            .map_err(|_| PlatformConfigInfoError::ParseDescriptor)?;

        let info_length = (&data[descriptor_size..header_size])
            .read_u32::<LittleEndian>()
            .map_err(|_| PlatformConfigInfoError::ReadInfoLength)?;

        let total_size = header_size + info_length as usize;

        let data = data
            .get(header_size..total_size)
            .ok_or(PlatformConfigInfoError::NotEnoughData)?;

        std::result::Result::Ok(Self {
            descriptor,
            info_length,
            data,
        })
    }
}

fn parse_kernel_parameters(kernel_parameters: &[u8]) -> Result<Map<String, Value>> {
    let parameters_str = String::from_utf8(kernel_parameters.to_vec())?;
    debug!("kernel parameters: {parameters_str}");

    let parameters = parameters_str
        .split(&[' ', '\n', '\r', '\0'])
        .collect::<Vec<&str>>()
        .iter()
        .filter_map(|item| {
            if item.is_empty() {
                return None;
            }

            let it = item.split_once('=');

            match it {
                Some((k, v)) => Some((k.into(), v.into())),
                None => Some((item.to_string(), Value::Null)),
            }
        })
        .collect();

    Ok(parameters)
}

#[derive(Debug, PartialEq)]
pub enum PlatformConfigInfoError {
    ParseDescriptor,
    ReadInfoLength,
    InvalidHeader,
    NotEnoughData,
}

/// The quote header. It is designed to compatible with earlier versions of the quote.
#[repr(C)]
#[derive(Debug, Pread)]
pub struct QuoteHeader {
    ///< 0:  The version this quote structure.
    pub version: [u8; 2],
    ///< 2:  sgx_attestation_algorithm_id_t.  Describes the type of signature in the signature_data[] field.
    pub att_key_type: [u8; 2],
    ///< 4:  Type of Trusted Execution Environment for which the Quote has been generated.
    ///      Supported values: 0 (SGX), 0x81(TDX)
    pub tee_type: [u8; 4],
    ///< 8:  Reserved field.
    pub reserved: [u8; 4],
    ///< 12: Unique identifier of QE Vendor.
    pub vendor_id: [u8; 16],
    ///< 28: Custom attestation key owner data.
    pub user_data: [u8; 20],
}

impl fmt::Display for QuoteHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Quote Header:
            \n\tVersion:\n\t{:X?}
            \n\tAttestation Signature Key Type:\n\t{:X?}
            \n\tTEE Type:\n\t{:X?}
            \n\tReserved:\n\t{:X?}
            \n\tVendor ID:\n\t{:X?}
            \n\tUser Data:\n\t{:X?}\n",
            hex::encode(self.version),
            hex::encode(self.att_key_type),
            hex::encode(self.tee_type),
            hex::encode(self.reserved),
            hex::encode(self.vendor_id),
            hex::encode(self.user_data)
        )
    }
}

/// SGX Report2 body
#[repr(C)]
#[derive(Debug, Pread)]
pub struct ReportBody2 {
    ///<  0:  TEE_TCB_SVN Array
    pub tcb_svn: [u8; 16],
    ///< 16:  Measurement of the SEAM module
    pub mr_seam: [u8; 48],
    ///< 64:  Measurement of a 3rd party SEAM module’s signer (SHA384 hash).
    ///       The value is 0’ed for Intel SEAM module
    pub mrsigner_seam: [u8; 48],
    ///< 112: MBZ: TDX 1.0
    pub seam_attributes: [u8; 8],
    ///< 120: TD's attributes
    pub td_attributes: [u8; 8],
    ///< 128: TD's XFAM
    pub xfam: [u8; 8],
    ///< 136: Measurement of the initial contents of the TD
    pub mr_td: [u8; 48],
    ///< 184: Software defined ID for non-owner-defined configuration on the guest TD. e.g., runtime or OS configuration
    pub mr_config_id: [u8; 48],
    ///< 232: Software defined ID for the guest TD's owner
    pub mr_owner: [u8; 48],
    ///< 280: Software defined ID for owner-defined configuration of the guest TD, e.g., specific to the workload rather than the runtime or OS
    pub mr_owner_config: [u8; 48],
    ///< 328: Array of 4(TDX1: NUM_RTMRS is 4) runtime extendable measurement registers
    pub rtmr_0: [u8; 48],
    pub rtmr_1: [u8; 48],
    pub rtmr_2: [u8; 48],
    pub rtmr_3: [u8; 48],
    ///< 520: Additional report data
    pub report_data: [u8; 64],
}

impl fmt::Display for ReportBody2 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Report Body:
            \n\tTCB SVN:\n\t{:X?}
            \n\tMRSEAM:\n\t{:X?}
            \n\tMRSIGNER_SEAM:\n\t{:X?}
            \n\tSEAM Attributes:\n\t{:X?}
            \n\tTD Attributes:\n\t{:X?}
            \n\tTD XFAM:\n\t{:X?}
            \n\tMRTD:\n\t{:X?}
            \n\tMRCONFIG ID:\n\t{:X?}
            \n\tMROWNER:\n\t{:X?}
            \n\tMROWNER_CONFIG:\n\t{:X?}
            \n\tRTMR[0]:\n\t{:X?}
            \n\tRTMR[1]:\n\t{:X?}
            \n\tRTMR[2]:\n\t{:X?}
            \n\tRTMR[3]:\n\t{:X?}
            \n\tReport Data:\n\t{:X?}",
            hex::encode(self.tcb_svn),
            hex::encode(self.mr_seam),
            hex::encode(self.mrsigner_seam),
            hex::encode(self.seam_attributes),
            hex::encode(self.td_attributes),
            hex::encode(self.xfam),
            hex::encode(self.mr_td),
            hex::encode(self.mr_config_id),
            hex::encode(self.mr_owner),
            hex::encode(self.mr_owner_config),
            hex::encode(self.rtmr_0),
            hex::encode(self.rtmr_1),
            hex::encode(self.rtmr_2),
            hex::encode(self.rtmr_3),
            hex::encode(self.report_data)
        )
    }
}

/// SGX Report2 body for quote v5
#[repr(C)]
#[derive(Debug, Pread)]
pub struct ReportBody2v15 {
    ///<  0:  TEE_TCB_SVN Array
    pub tcb_svn: [u8; 16],
    ///< 16:  Measurement of the SEAM module
    pub mr_seam: [u8; 48],
    ///< 64:  Measurement of a 3rd party SEAM module’s signer (SHA384 hash).
    ///       The value is 0’ed for Intel SEAM module
    pub mrsigner_seam: [u8; 48],
    ///< 112: MBZ: TDX 1.0
    pub seam_attributes: [u8; 8],
    ///< 120: TD's attributes
    pub td_attributes: [u8; 8],
    ///< 128: TD's XFAM
    pub xfam: [u8; 8],
    ///< 136: Measurement of the initial contents of the TD
    pub mr_td: [u8; 48],
    ///< 184: Software defined ID for non-owner-defined configuration on
    /// the guest TD. e.g., runtime or OS configuration
    pub mr_config_id: [u8; 48],
    ///< 232: Software defined ID for the guest TD's owner
    pub mr_owner: [u8; 48],
    ///< 280: Software defined ID for owner-defined configuration of the
    /// guest TD, e.g., specific to the workload rather than the runtime or OS
    pub mr_owner_config: [u8; 48],
    ///< 328: Array of 4(TDX1: NUM_RTMRS is 4) runtime extendable
    /// measurement registers
    pub rtmr_0: [u8; 48],
    pub rtmr_1: [u8; 48],
    pub rtmr_2: [u8; 48],
    pub rtmr_3: [u8; 48],
    ///< 520: Additional report data
    pub report_data: [u8; 64],
    ///< 584: Array of TEE TCB SVNs (for TD preserving).
    pub tee_tcb_svn2: [u8; 16],
    ///< 600: If is one or more bound or pre-bound service TDs, SERVTD_HASH is
    /// the SHA384 hash of the TDINFO_STRUCTs of those service TDs bound.
    /// Else, SERVTD_HASH is 0.
    pub mr_servicetd: [u8; 48],
}

impl fmt::Display for ReportBody2v15 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Report Body:
            \n\tTCB SVN:\n\t{:X?}
            \n\tMRSEAM:\n\t{:X?}
            \n\tMRSIGNER_SEAM:\n\t{:X?}
            \n\tSEAM Attributes:\n\t{:X?}
            \n\tTD Attributes:\n\t{:X?}
            \n\tTD XFAM:\n\t{:X?}
            \n\tMRTD:\n\t{:X?}
            \n\tMRCONFIG ID:\n\t{:X?}
            \n\tMROWNER:\n\t{:X?}
            \n\tMROWNER_CONFIG:\n\t{:X?}
            \n\tRTMR[0]:\n\t{:X?}
            \n\tRTMR[1]:\n\t{:X?}
            \n\tRTMR[2]:\n\t{:X?}
            \n\tRTMR[3]:\n\t{:X?}
            \n\tReport Data:\n\t{:X?}
            \n\tTEE TCB SVN2:\n\t{:X?}
            \n\tMR SERVICETD:\n\t{:X?}",
            hex::encode(self.tcb_svn),
            hex::encode(self.mr_seam),
            hex::encode(self.mrsigner_seam),
            hex::encode(self.seam_attributes),
            hex::encode(self.td_attributes),
            hex::encode(self.xfam),
            hex::encode(self.mr_td),
            hex::encode(self.mr_config_id),
            hex::encode(self.mr_owner),
            hex::encode(self.mr_owner_config),
            hex::encode(self.rtmr_0),
            hex::encode(self.rtmr_1),
            hex::encode(self.rtmr_2),
            hex::encode(self.rtmr_3),
            hex::encode(self.report_data),
            hex::encode(self.tee_tcb_svn2),
            hex::encode(self.mr_servicetd)
        )
    }
}

#[repr(u16)]
#[derive(Debug)]
pub enum QuoteV5Type {
    TDX10 = 2,
    TDX15 = 3,
}

impl fmt::Display for QuoteV5Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            QuoteV5Type::TDX10 => writeln!(f, "Quote v5 Type: TDX 1.0"),
            QuoteV5Type::TDX15 => writeln!(f, "Quote v5 Type: TDX 1.5"),
        }
    }
}

impl QuoteV5Type {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 2 {
            bail!("parse QuoteV5 Type failed. Bytes length < 2 bytes");
        }
        let mut r#type: [u8; 2] = [0; 2];
        r#type.copy_from_slice(&bytes[0..2]);
        let r#type = u16::from_le_bytes(r#type);
        let r#type = match r#type {
            2 => QuoteV5Type::TDX10,
            3 => QuoteV5Type::TDX15,
            others => bail!("parse QuoteV5 Type failed. {others} not defined."),
        };

        Ok(r#type)
    }

    pub fn as_bytes(&self) -> [u8; 2] {
        // The unsafe here is ok as it is marked as repr(u16)
        unsafe {
            let raw_value: u16 = *(self as *const QuoteV5Type as *const u16);
            raw_value.to_ne_bytes()
        }
    }
}

pub enum QuoteV5Body {
    Tdx10(ReportBody2),
    Tdx15(ReportBody2v15),
}

impl fmt::Display for QuoteV5Body {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            QuoteV5Body::Tdx10(body) => write!(f, "{}", body),
            QuoteV5Body::Tdx15(body) => write!(f, "{}", body),
        }
    }
}

pub enum Quote {
    /// TD Quote Payload(Version 4)
    /// First 632 bytes of TD Quote
    /// Excluding the signature data attached at the end of the Quote.
    ///
    /// Refer to: https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_4.h#L141
    V4 {
        header: QuoteHeader,
        body: ReportBody2,
    },

    /// TD Quote Payload(Version 5)
    /// First 638 bytes of TD Quote
    /// Excluding the signature data attached at the end of the Quote.
    ///
    /// Refer to: https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_5.h#L106
    V5 {
        header: QuoteHeader,
        r#type: QuoteV5Type,
        size: [u8; 4],
        body: QuoteV5Body,
    },
}

macro_rules! body_field {
    ($r: ident) => {
        pub fn $r(&self) -> &[u8] {
            match self {
                Quote::V4 { body, .. } => &body.$r,
                Quote::V5 { body, .. } => match body {
                    QuoteV5Body::Tdx10(body) => &body.$r,
                    QuoteV5Body::Tdx15(body) => &body.$r,
                },
            }
        }
    };
}

impl Quote {
    body_field!(report_data);
    body_field!(mr_config_id);
    body_field!(rtmr_0);
    body_field!(rtmr_1);
    body_field!(rtmr_2);
    body_field!(rtmr_3);
}

impl fmt::Display for Quote {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Quote::V4 { header, body } => write!(f, "TD Quote (V4):\n{header}\n{body}\n"),
            Quote::V5 {
                header,
                r#type,
                size,
                body,
            } => write!(
                f,
                "TD Quote (V5):\n{header}\n{type}\n{}\n{body}\n",
                hex::encode(size)
            ),
        }
    }
}

pub const QUOTE_HEADER_SIZE: usize = 48;

pub fn parse_tdx_quote(quote_bin: &[u8]) -> Result<Quote> {
    let quote_header = &quote_bin[..QUOTE_HEADER_SIZE];
    let header = quote_header
        .pread::<QuoteHeader>(0)
        .map_err(|e| anyhow!("Parse TD quote header failed: {:?}", e))?;

    match header.version {
        [4, 0] => {
            let body: ReportBody2 = quote_bin
                .pread::<ReportBody2>(QUOTE_HEADER_SIZE)
                .map_err(|e| anyhow!("Parse TD quote v4 body failed: {:?}", e))?;
            Ok(Quote::V4 { header, body })
        }
        [5, 0] => {
            let r#type = QuoteV5Type::from_bytes(
                &quote_bin
                    [QUOTE_HEADER_SIZE..QUOTE_HEADER_SIZE + std::mem::size_of::<QuoteV5Type>()],
            )?;
            let mut size: [u8; 4] = [0; 4];
            size.copy_from_slice(
                &quote_bin[QUOTE_HEADER_SIZE + std::mem::size_of::<QuoteV5Type>()
                    ..QUOTE_HEADER_SIZE
                        + std::mem::size_of::<QuoteV5Type>()
                        + std::mem::size_of::<[u8; 4]>()],
            );
            match r#type {
                QuoteV5Type::TDX10 => {
                    let offset = QUOTE_HEADER_SIZE
                        + std::mem::size_of::<QuoteV5Type>()
                        + std::mem::size_of::<[u8; 4]>();
                    let body: ReportBody2 = quote_bin
                        .pread::<ReportBody2>(offset)
                        .map_err(|e| anyhow!("Parse TD quote v5 TDX1.0 body failed: {:?}", e))?;
                    Ok(Quote::V5 {
                        header,
                        r#type,
                        size,
                        body: QuoteV5Body::Tdx10(body),
                    })
                }
                QuoteV5Type::TDX15 => {
                    let offset = QUOTE_HEADER_SIZE
                        + std::mem::size_of::<QuoteV5Type>()
                        + std::mem::size_of::<[u8; 4]>();
                    let body: ReportBody2v15 = quote_bin
                        .pread::<ReportBody2v15>(offset)
                        .map_err(|e| anyhow!("Parse TD quote v5 TDX1.5 body failed: {:?}", e))?;
                    Ok(Quote::V5 {
                        header,
                        r#type,
                        size,
                        body: QuoteV5Body::Tdx15(body),
                    })
                }
            }
        }
        _ => Err(anyhow!("Quote version not defined.")),
    }
}

#[derive(Debug, Clone, EnumString, Display)]
pub enum MeasuredEntity {
    #[strum(serialize = "td_hob\0")]
    TdShim,
    #[strum(serialize = "td_payload\0")]
    TdShimKernel,
    #[strum(serialize = "td_payload_info\0")]
    TdShimKernelParams,
    #[strum(serialize = "k\0e\0r\0n\0e\0l\0")]
    TdvfKernel,
}

#[derive(Debug, Clone, Copy)]
pub struct Rtmr {
    pub rtmr0: [u8; 48],
    pub rtmr1: [u8; 48],
    pub rtmr2: [u8; 48],
    pub rtmr3: [u8; 48],
}

#[derive(Clone)]
pub struct CcEventLog {
    pub cc_events: Eventlog,
}

impl TryFrom<Vec<u8>> for CcEventLog {
    type Error = anyhow::Error;
    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self {
            cc_events: Eventlog::try_from(data)?,
        })
    }
}

impl CcEventLog {
    pub fn integrity_check(&self, rtmr_from_quote: Rtmr) -> Result<()> {
        let rtmr_eventlog = self.rebuild_rtmr()?;

        // Compare rtmr values from tdquote and EventLog acpi table
        if rtmr_from_quote.rtmr0 != rtmr_eventlog.rtmr0
            || rtmr_from_quote.rtmr1 != rtmr_eventlog.rtmr1
            || rtmr_from_quote.rtmr2 != rtmr_eventlog.rtmr2
        {
            bail!("RTMR 0, 1, 2 values from TD quote is not equal with the values from EventLog");
        }

        Ok(())
    }

    fn rebuild_rtmr(&self) -> Result<Rtmr> {
        let mr_map = self.cc_events.replay_measurement_regiestry();

        let mr = Rtmr {
            rtmr0: mr_map.get(&1).unwrap_or(&Vec::from([0u8; 48]))[0..48].try_into()?,
            rtmr1: mr_map.get(&2).unwrap_or(&Vec::from([0u8; 48]))[0..48].try_into()?,
            rtmr2: mr_map.get(&3).unwrap_or(&Vec::from([0u8; 48]))[0..48].try_into()?,
            rtmr3: mr_map.get(&4).unwrap_or(&Vec::from([0u8; 48]))[0..48].try_into()?,
        };

        Ok(mr)
    }

    pub fn query_digest(&self, entity: MeasuredEntity) -> Option<String> {
        let event_desc_prefix = Self::generate_query_key_prefix(entity)?;

        for event_entry in self.cc_events.log.clone() {
            if event_entry.event_desc.len() < event_desc_prefix.len() {
                continue;
            }
            if &event_entry.event_desc[..event_desc_prefix.len()] == event_desc_prefix.as_slice() {
                let digest = &event_entry.digests[0].digest;
                return Some(hex::encode(digest));
            }
        }
        None
    }

    #[allow(dead_code)]
    pub fn query_event_data(&self, entity: MeasuredEntity) -> Option<Vec<u8>> {
        let event_desc_prefix = Self::generate_query_key_prefix(entity)?;

        for event_entry in self.cc_events.log.clone() {
            if event_entry.event_desc.len() < event_desc_prefix.len() {
                continue;
            }
            if &event_entry.event_desc[..event_desc_prefix.len()] == event_desc_prefix.as_slice() {
                return Some(event_entry.event_desc);
            }
        }
        None
    }

    #[allow(unused_assignments)]
    fn generate_query_key_prefix(entity: MeasuredEntity) -> Option<Vec<u8>> {
        let mut event_desc_prefix = Vec::new();
        match entity {
            MeasuredEntity::TdShimKernel => {
                // Event data is in UEFI_PLATFORM_FIRMWARE_BLOB2 format
                // Defined in TCG PC Client Platform Firmware Profile Specification section
                // 'UEFI_PLATFORM_FIRMWARE_BLOB Structure Definition'
                let entity_name = entity.to_string();
                event_desc_prefix = vec![entity_name.as_bytes().len() as u8];
                event_desc_prefix.extend_from_slice(entity_name.as_bytes());
            }
            MeasuredEntity::TdvfKernel => {
                event_desc_prefix = entity.to_string().as_bytes().to_vec();
            }
            MeasuredEntity::TdShim | MeasuredEntity::TdShimKernelParams => {
                // Event data is in TD_SHIM_PLATFORM_CONFIG_INFO format
                // Defined in td-shim spec 'Table 3.5-4 TD_SHIM_PLATFORM_CONFIG_INFO'
                // link: https://github.com/confidential-containers/td-shim/blob/main/doc/tdshim_spec.md
                event_desc_prefix = entity.to_string().as_bytes().to_vec();
            }
        }
        Some(event_desc_prefix)
    }
}

#[derive(Clone)]
pub struct AAEvent {
    pub domain: String,
    pub operation: String,
    pub content: String,
}

impl FromStr for AAEvent {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self> {
        let input_trimed = input.trim_end();
        let sections: Vec<&str> = input_trimed.split(' ').collect();
        if sections.len() != 3 {
            bail!("Illegal AA event entry format. Should be `<domain> <operation> <content>`");
        }
        Ok(Self {
            domain: sections[0].into(),
            operation: sections[1].into(),
            content: sections[2].into(),
        })
    }
}

#[derive(Clone)]
pub struct AAEventlog {
    pub hash_algorithm: HashAlgorithm,
    pub init_state: Vec<u8>,
    pub events: Vec<AAEvent>,
}

impl FromStr for AAEventlog {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self> {
        let all_lines = input.lines().collect::<Vec<&str>>();

        let (initline, eventlines) = all_lines
            .split_first()
            .ok_or(anyhow!("at least one line should be included in AAEL"))?;

        // Init line looks like
        // INIT sha256/0000000000000000000000000000000000000000000000000000000000000000
        let init_line_items = initline.split_ascii_whitespace().collect::<Vec<&str>>();
        if init_line_items.len() != 2 {
            bail!("Illegal INIT event record.");
        }

        if init_line_items[0] != "INIT" {
            bail!("INIT event should start with `INIT` key word");
        }

        let (hash_algorithm, init_state) = init_line_items[1].split_once('/').ok_or(anyhow!(
            "INIT event should have `<sha-algorithm>/<init-PCR-value>` as content after `INIT`"
        ))?;

        let hash_algorithm = hash_algorithm
            .try_into()
            .context("parse Hash Algorithm in INIT entry")?;
        let init_state = hex::decode(init_state).context("parse init state in INIT entry")?;

        let events = eventlines
            .iter()
            .map(|line| AAEvent::from_str(line))
            .collect::<Result<Vec<AAEvent>>>()?;

        Ok(Self {
            events,
            hash_algorithm,
            init_state,
        })
    }
}

impl AAEventlog {
    fn accumulate_hash<D: Digest + FixedOutput>(&self) -> Vec<u8> {
        let mut state = self.init_state.clone();

        let mut init_event_hasher = D::new();
        let init_event = format!(
            "INIT {}/{}",
            self.hash_algorithm.as_ref(),
            hex::encode(&self.init_state)
        );
        Digest::update(&mut init_event_hasher, init_event.as_bytes());
        let init_event_hash = init_event_hasher.finalize();

        let mut hasher = D::new();
        Digest::update(&mut hasher, &state);

        Digest::update(&mut hasher, init_event_hash);
        state = hasher.finalize().to_vec();

        self.events.iter().for_each(|event| {
            let mut event_hasher = D::new();
            Digest::update(&mut event_hasher, event.domain.as_bytes());
            Digest::update(&mut event_hasher, b" ");
            Digest::update(&mut event_hasher, event.operation.as_bytes());
            Digest::update(&mut event_hasher, b" ");
            Digest::update(&mut event_hasher, event.content.as_bytes());
            let event_hash = event_hasher.finalize();

            let mut hasher = D::new();
            Digest::update(&mut hasher, &state);
            Digest::update(&mut hasher, event_hash);
            state = hasher.finalize().to_vec();
        });

        state
    }

    /// Check the integrity of the AAEL, and gets a digest. The digest should be the same
    /// as the input `rtmr`, or the integrity check will fail.
    pub fn integrity_check(&self, rtmr: &[u8]) -> Result<()> {
        let result = match self.hash_algorithm {
            HashAlgorithm::Sha256 => self.accumulate_hash::<Sha256>(),
            HashAlgorithm::Sha384 => self.accumulate_hash::<Sha384>(),
            HashAlgorithm::Sha512 => self.accumulate_hash::<Sha512>(),
        };

        if rtmr != result {
            bail!(
                "AA eventlog does not pass check. AAEL value : {}, Quote value {}",
                hex::encode(result),
                hex::encode(rtmr)
            );
        }

        Ok(())
    }

    pub fn to_parsed_claims(&self) -> Map<String, Value> {
        let mut aael = Map::new();
        for eventlog in &self.events {
            let key = format!("{}/{}", eventlog.domain, eventlog.operation);
            let item = Value::String(eventlog.content.clone());
            match aael.get_mut(&key) {
                Some(value) => value
                    .as_array_mut()
                    .expect("Only array can be inserted")
                    .push(item),
                None => {
                    // This insertion will ensure the value in AAEL always be
                    // `Array`s. This will make `as_array_mut()` always result
                    // in `Some`.
                    aael.insert(key, Value::Array(vec![item]));
                }
            }
        }

        aael
    }
}

/// Hash algorithms used to calculate eventlog
#[derive(EnumString, AsRefStr, Clone)]
pub enum HashAlgorithm {
    #[strum(ascii_case_insensitive)]
    #[strum(serialize = "sha256")]
    Sha256,

    #[strum(ascii_case_insensitive)]
    #[strum(serialize = "sha384")]
    Sha384,

    #[strum(ascii_case_insensitive)]
    #[strum(serialize = "sha512")]
    Sha512,
}

pub fn extend_claim_with_tpm_quote(
    claim: &mut TeeEvidenceParsedClaim,
    quote: &TpmQuote,
) -> Result<()> {
    let Value::Object(ref mut map) = claim else {
        bail!("failed to extend the claim, not an object");
    };

    let mut tpm_values = serde_json::Map::new();
    for (i, pcr) in quote.pcrs_sha256().enumerate() {
        tpm_values.insert(format!("pcr{:02}", i), Value::String(hex::encode(pcr)));
    }
    debug!("extending claim with TPM quote: {:#?}", tpm_values);
    map.insert("tpm".to_string(), Value::Object(tpm_values));

    Ok(())
}

#[test]
#[ignore]
fn test_get_tdx_evidence_claims() -> Result<(), anyhow::Error> {
    let path = "./src/coco_as/examples/tdx_byte_evidence.txt";
    let tdx_evidence: Vec<u8> = crate::utils::test_utils::read_vector_txt(path.to_string())?;

    get_tdx_evidence_claims(tdx_evidence)?;

    Ok(())
}
