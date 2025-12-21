use crate::extension::Extension;
use anyhow::{Result, bail};

/// struct {
///     uint32 ticket_lifetime;
///     uint32 ticket_age_add;
///     opaque ticket_nonce<0..255>;
///     opaque ticket<1..2^16-1>;
///     Extension extensions<0..2^16-2>;
/// } NewSessionTicket;
///
/// ticket_lifetime:  Indicates the lifetime in seconds as a 32-bit
/// unsigned integer in network byte order from the time of ticket
/// issuance.  Servers MUST NOT use any value greater than
/// 604800 seconds (7 days).  The value of zero indicates that the
/// ticket should be discarded immediately.  Clients MUST NOT cache
/// tickets for longer than 7 days, regardless of the ticket_lifetime,
/// and MAY delete tickets earlier based on local policy.  A server
/// MAY treat a ticket as valid for a shorter period of time than what
/// is stated in the ticket_lifetime.
///
/// ticket_age_add:  A securely generated, random 32-bit value that is
/// used to obscure the age of the ticket that the client includes in
/// the "pre_shared_key" extension.  The client-side ticket age is
/// added to this value modulo 2^32 to obtain the value that is
/// transmitted by the client.  The server MUST generate a fresh value
/// for each ticket it sends.
///
/// ticket_nonce:  A per-ticket value that is unique across all tickets
/// issued on this connection.
///
/// ticket:  The value of the ticket to be used as the PSK identity.  The
/// ticket itself is an opaque label.  It MAY be either a database
/// lookup key or a self-encrypted and self-authenticated value.
///
/// extensions:  A set of extension values for the ticket.  The
/// "Extension" format is defined in Section 4.2.  Clients MUST ignore
/// unrecognized extensions.
#[derive(Debug)]
pub struct NewSessionTicket {
    ticket_lifetime: u32,
    ticket_age_add: u32,
    ticket_nonce: Vec<u8>,
    ticket: Vec<u8>,
    extensions: Vec<Extension>,
}

impl NewSessionTicket {
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut offset = 0;
        if offset + 4 > data.len() {
            bail!("Ticket size is too small");
        }
        let ticket_lifetime = u32::from_be_bytes(data[offset..offset + 4].try_into()?);
        offset += 4;
        if offset + 4 > data.len() {
            bail!("Ticket size is too small for ticket_age_add");
        }
        let ticket_age_add = u32::from_be_bytes(data[offset..offset + 4].try_into()?);
        offset += 4;
        let nonce_len = data[offset];
        offset += 1;
        if offset + nonce_len as usize > data.len() {
            bail!("Ticket size is too small for nonce");
        }
        let ticket_nonce = data[offset..offset + nonce_len as usize].to_vec();
        offset += nonce_len as usize;
        let ticket_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        let mut ticket = data[offset..offset + ticket_len].to_vec();
        offset += ticket_len;
        let (extensions, _) = Extension::list_from_bytes(&data[offset..], false)?;
        Ok(Self {
            ticket_lifetime,
            ticket_age_add,
            ticket_nonce,
            ticket,
            extensions,
        })
    }
}
