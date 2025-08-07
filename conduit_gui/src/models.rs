use serde::Deserialize;

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct ImpInfo {
    pub session: String,
    pub ip: String,
    pub username: String,
    pub domain: String,
    pub os: String,
    pub imp_pid: String,
    pub process_name: String,
    pub sleep: String,
    pub last_check_in: String,
}

impl ImpInfo {
    pub fn short_session(&self) -> String {
        let s = self.session.clone();
        s.chars()
            .rev()
            .take(8)
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>()
    }
}


