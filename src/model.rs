// model.rs — data structures for recon findings (serde-serializable).
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Default)]
pub struct WhoisIp {
    pub ip: String,
    pub netname: String,
    pub org: String,
    pub country: String,
    pub asn: String,
    pub route: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Seo {
    pub title: String,
    pub h1: Vec<String>,
    pub wordcount: usize,
    pub kw_hits: Vec<String>,
    pub kw_density_pct: f64,
    pub seo_score: u32,
    pub doorwayish: bool,
    pub outbound_hosts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Tech {
    pub tech: Vec<String>,
    pub generator: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct PaymentsContacts {
    pub payments: Vec<String>,
    pub contacts: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Hacked {
    pub flag: String,
    pub reason: String,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub host: String,
    pub ips: Vec<String>,
    pub whois: Vec<WhoisIp>,
    pub http_status: Option<u16>,
    pub final_url: Option<String>,
    pub redirect: Vec<String>,
    pub domain_created: Option<String>,
    pub domain_age_days: Option<i64>,
    pub crt_subdomains: Vec<String>,
    pub tls_sans: Vec<String>,
    pub sibling_count: usize,
    pub tech: Tech,
    pub payments: Vec<String>,
    pub contacts: BTreeMap<String, Vec<String>>,
    pub seo: Seo,
    pub risk: u32,
    pub tier: String,
    pub hacked: Option<Hacked>,
    pub backlinks: Vec<String>,
    #[serde(skip)]
    pub landing_html: String,
    pub ref_hosts: Vec<String>,
}

impl Default for Finding {
    fn default() -> Self {
        Finding {
            host: String::new(),
            ips: Vec::new(),
            whois: Vec::new(),
            http_status: None,
            final_url: None,
            redirect: Vec::new(),
            domain_created: None,
            domain_age_days: None,
            crt_subdomains: Vec::new(),
            tls_sans: Vec::new(),
            sibling_count: 0,
            tech: Tech::default(),
            payments: Vec::new(),
            contacts: BTreeMap::new(),
            seo: Seo::default(),
            risk: 0,
            tier: "LOW".into(),
            hacked: None,
            backlinks: Vec::new(),
            landing_html: String::new(),
            ref_hosts: Vec::new(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub generated_at: String,
    pub summary: Summary,
    pub findings: Vec<Finding>,
    pub hacked_flags: Vec<Finding>,
    pub asn_groups: BTreeMap<String, Vec<String>>,
    pub backlinks: Vec<BacklinkRow>,
}

#[derive(Debug, Serialize)]
pub struct Summary {
    pub seeds: usize,
    pub resolved: usize,
    pub findings: usize,
    pub flagged_hacked: usize,
    pub critical: usize,
}

#[derive(Debug, Serialize)]
pub struct BacklinkRow {
    pub host: String,
    pub outbound: Vec<String>,
}