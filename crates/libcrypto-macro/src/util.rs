use syn::{parse::ParseStream, Result, Token};

/// Skips the next token if it's a comma.
pub(crate) fn skip_comma(input: ParseStream<'_>) -> Result<()> {
    let lookahead = input.lookahead1();
    if lookahead.peek(Token![,]) {
        let _: Token![,] = input.parse()?;
    }
    Ok(())
}
