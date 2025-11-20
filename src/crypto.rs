/// struct {
///     uint16 length = Length;
///     opaque label<7..255> = "tls13 " + Label;
///     opaque context<0..255> = Context;
/// } HkdfLabel;
struct HkdfLabel {
    length: u16,
    label: &'static str,
    context: Vec<u8>,
}
