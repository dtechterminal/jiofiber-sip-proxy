use std::collections::HashMap;

use anyhow::{Context, Result, ensure};

use crate::{
    config::{SipConfig, USER_AGENT},
    sip::{self, Dialog, Endpoint, Message},
    upstream::{self, ALLOW},
};

pub enum InviteEvent {
    Ignore,
    Retry,
    Progress(u16),
    Answer,
    Reject(u16),
}

pub struct Invitation {
    pub request: Message,
    pub dialog: Option<Dialog>,
    endpoint: Endpoint,
    pracks: HashMap<(String, u32), Message>,
    last_rseq: HashMap<String, u32>,
    next_seq: u32,
    retries: u8,
    provisional: bool,
    cancelled: bool,
    cancel_sent: bool,
    answered: bool,
    final_acks: HashMap<(String, u32), Message>,
}

impl Invitation {
    pub fn new(endpoint: &Endpoint, from_uri: &str, target: &str, sdp: String, ims: bool) -> Self {
        let from = format!("<{from_uri}>;tag={}", sip::id());
        let mut request = endpoint.request(
            "INVITE",
            target,
            &from,
            &format!("<{target}>"),
            &sip::id(),
            1,
        );
        request.add("Contact", &endpoint.contact);
        request.add("Supported", "100rel");
        request.add("Allow", ALLOW);
        request.add("User-Agent", USER_AGENT);
        if ims {
            request.add("P-Access-Network-Info", "GPON");
            request.add("P-Preferred-Identity", format!("<{from_uri}>"));
        }
        request.set_sdp(sdp);
        Self {
            request,
            endpoint: endpoint.clone(),
            dialog: None,
            pracks: HashMap::new(),
            last_rseq: HashMap::new(),
            next_seq: 1,
            retries: 0,
            provisional: false,
            cancelled: false,
            cancel_sent: false,
            answered: false,
            final_acks: HashMap::new(),
        }
    }

    fn cancel_request(&mut self) -> Option<Message> {
        if self.cancelled && self.provisional && !self.cancel_sent && !self.answered {
            self.cancel_sent = true;
            Some(sip::related_request(&self.request, "CANCEL", None))
        } else {
            None
        }
    }

    pub fn cancel(&mut self) -> Option<Message> {
        self.cancelled = true;
        self.cancel_request()
    }

    pub fn cancelled(&self) -> bool {
        self.cancelled
    }

    pub fn handle(
        &mut self,
        response: &Message,
        cfg: Option<&SipConfig>,
    ) -> Result<(InviteEvent, Vec<Message>)> {
        let mut send = Vec::new();
        let (Some((status, _)), Some((seq, method))) = (response.status(), response.cseq()) else {
            return Ok((InviteEvent::Ignore, send));
        };
        if response.header("Call-ID") != self.request.header("Call-ID") || method != "INVITE" {
            return Ok((InviteEvent::Ignore, send));
        }
        let to = response.header("To").context("INVITE response has no To")?;
        let to_tag = sip::parameter(to, "tag").unwrap_or("");
        let key = (to_tag.to_owned(), seq);
        if status >= 200
            && let Some(ack) = self.final_acks.get(&key)
        {
            return Ok((InviteEvent::Ignore, vec![ack.clone()]));
        }
        if !response.transaction_matches(&self.request) {
            return Ok((InviteEvent::Ignore, send));
        }
        let event = match status {
            100..=199 => {
                self.provisional = true;
                if (101..200).contains(&status)
                    && let Some(rseq) = response.header("RSeq")
                {
                    let rseq = rseq.parse::<u32>().context("invalid RSeq")?;
                    ensure!((1..=0x7fff_ffff).contains(&rseq), "invalid RSeq");
                    let key = (to_tag.to_owned(), rseq);
                    if let Some(prack) = self.pracks.get(&key) {
                        return Ok((InviteEvent::Ignore, vec![prack.clone()]));
                    }
                    if self
                        .last_rseq
                        .get(to_tag)
                        .is_some_and(|previous| previous.checked_add(1) != Some(rseq))
                    {
                        return Ok((InviteEvent::Ignore, send));
                    }
                    let mut dialog = Dialog::outgoing(&self.request, response)?;
                    self.last_rseq.insert(to_tag.to_owned(), rseq);
                    dialog.seq = self.next_seq;
                    let mut prack = dialog.next_request(&self.endpoint, "PRACK");
                    self.next_seq = dialog.seq;
                    prack.add("RAck", format!("{rseq} {seq} INVITE"));
                    self.pracks.insert(key, prack.clone());
                    send.push(prack);
                }
                send.extend(self.cancel_request());
                InviteEvent::Progress(status)
            }
            200..=299 => {
                let mut dialog = Dialog::outgoing(&self.request, response)?;
                dialog.seq = self.next_seq;
                let ack = dialog.request(&self.endpoint, "ACK", seq);
                self.final_acks.insert(key, ack.clone());
                send.push(ack);
                if self.answered {
                    // Final responses from additional forks still require ACK and BYE.
                    send.push(dialog.next_request(&self.endpoint, "BYE"));
                    InviteEvent::Ignore
                } else {
                    self.answered = true;
                    self.dialog = Some(dialog);
                    InviteEvent::Answer
                }
            }
            300..=699 => {
                let ack = sip::related_request(&self.request, "ACK", Some(to));
                self.final_acks.insert(key, ack.clone());
                send.push(ack);
                if let Some(cfg) = cfg
                    .filter(|_| matches!(status, 401 | 407) && self.retries < 1 && !self.cancelled)
                    && let Ok((header, value)) = upstream::auth(
                        cfg,
                        response,
                        status,
                        "INVITE",
                        self.request.uri().unwrap_or_default(),
                    )
                {
                    self.retries += 1;
                    self.next_seq += 1;
                    self.provisional = false;
                    self.pracks.clear();
                    self.last_rseq.clear();
                    self.request.headers.retain(|(name, _)| {
                        !["Via", "CSeq", "Authorization", "Proxy-Authorization"]
                            .contains(&name.as_str())
                    });
                    self.request
                        .headers
                        .insert(0, ("Via".into(), self.endpoint.via()));
                    self.request
                        .add("CSeq", format!("{} INVITE", self.next_seq));
                    self.request.add(header, value);
                    send.push(self.request.clone());
                    InviteEvent::Retry
                } else {
                    InviteEvent::Reject(status)
                }
            }
            _ => InviteEvent::Ignore,
        };
        Ok((event, send))
    }

    pub fn bye(&mut self) -> Option<Message> {
        self.dialog
            .as_mut()
            .map(|dialog| dialog.next_request(&self.endpoint, "BYE"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prack_and_ack_use_the_authenticated_invite_cseq() -> Result<()> {
        let endpoint = Endpoint {
            addr: "[::1]:5061".parse()?,
            transport: "TLS",
            contact: "<sip:caller@[::1]:5061>".into(),
        };
        let cfg = SipConfig {
            public_id: "sip:caller@example.test".into(),
            auth_user: "caller".into(),
            password: "test-password".into(),
            registrar: "example.test".into(),
            realm: "example.test".into(),
            proxy: "[::1]".into(),
        };
        let mut invite = Invitation::new(
            &endpoint,
            &cfg.public_id,
            "sip:callee@example.test",
            "v=0".into(),
            true,
        );
        let mut challenge = Message::response(
            &invite.request,
            407,
            "Proxy Authentication Required",
            Some("challenge"),
        );
        challenge.add(
            "Proxy-Authenticate",
            r#"Digest realm="example.test", nonce="test", qop="auth,auth-int", opaque="other""#,
        );
        let (event, retry) = invite.handle(&challenge, Some(&cfg))?;
        assert!(matches!(event, InviteEvent::Retry));
        assert_eq!(retry[0].cseq(), Some((1, "ACK")));
        assert_eq!(retry[0].via_branch(), challenge.via_branch());
        assert_eq!(retry[1].cseq(), Some((2, "INVITE")));
        assert!(
            retry[1]
                .header("Proxy-Authorization")
                .unwrap()
                .contains("qop=auth")
        );

        let mut provisional =
            Message::response(&invite.request, 183, "Session Progress", Some("remote"));
        provisional.add("RSeq", "123");
        provisional.add("Contact", "<sip:callee@callee.example.test>");
        provisional.add(
            "Record-Route",
            "<sip:one.example.test;lr>, <sip:two.example.test;lr>",
        );
        let (_, prack) = invite.handle(&provisional, Some(&cfg))?;
        assert_eq!(prack[0].cseq(), Some((3, "PRACK")));
        assert_eq!(prack[0].header("RAck"), Some("123 2 INVITE"));
        assert_eq!(prack[0].uri(), Some("sip:callee@callee.example.test"));
        assert_eq!(
            prack[0].values("Route").collect::<Vec<_>>(),
            ["<sip:two.example.test;lr>", "<sip:one.example.test;lr>"]
        );
        let (_, resent) = invite.handle(&provisional, Some(&cfg))?;
        assert_eq!(resent[0].encode(), prack[0].encode());

        let ok = Message::response(&invite.request, 200, "OK", Some("remote"));
        let (event, ack) = invite.handle(&ok, Some(&cfg))?;
        assert!(matches!(event, InviteEvent::Answer));
        assert_eq!(ack[0].cseq(), Some((2, "ACK")));
        assert_ne!(ack[0].via_branch(), ok.via_branch());
        assert_eq!(invite.bye().unwrap().cseq(), Some((4, "BYE")));
        Ok(())
    }
}
