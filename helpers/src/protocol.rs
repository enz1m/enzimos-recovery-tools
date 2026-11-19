// SPDX-License-Identifier: MIT
//! Private authenticated pipes keep browsing separate from fresh mutation requests.
use enzimos_platform::{Error, Result, json, require};
use serde_json::{Value, json as value};
use std::io::{BufRead, Write};
pub const MAX_REQUEST: usize = 65536;
pub fn read_line<R: BufRead>(input: &mut R) -> Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    loop {
        let available = input.fill_buf()?;
        if available.is_empty() {
            break;
        }
        let take = available
            .iter()
            .position(|b| *b == b'\n')
            .map_or(available.len(), |p| p + 1);
        require(
            bytes.len() + take <= MAX_REQUEST + 1,
            "Recovery request is too large.",
        )?;
        bytes.extend_from_slice(&available[..take]);
        input.consume(take);
        if bytes.last() == Some(&b'\n') {
            break;
        }
    }
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    require(bytes.len() <= MAX_REQUEST, "Recovery request is too large.")?;
    Ok(Some(bytes))
}
pub fn emit<W: Write>(output: &mut W, value: &Value) -> Result<()> {
    let mut bytes = json::canonical(value)?;
    require(
        bytes.len() <= 32 * 1024 * 1024,
        "Recovery response is too large.",
    )?;
    bytes.push(b'\n');
    output.write_all(&bytes)?;
    output.flush()?;
    Ok(())
}
pub fn browse_action(request: &Value) -> Result<&str> {
    let action = request["action"]
        .as_str()
        .ok_or_else(|| Error("Recovery action is missing.".into()))?;
    require(
        matches!(action, "files_list" | "files_destination" | "files_drives"),
        "This connection is for browsing only.",
    )?;
    Ok(action)
}
/// The executor rechecks the authenticated account for every request. Mutations
/// never enter through a persistent browse pipe, including disguised stream flags.
pub fn serve<R, W, F>(initial: Value, input: &mut R, output: &mut W, mut executor: F) -> Result<()>
where
    R: BufRead,
    W: Write,
    F: FnMut(&Value, &mut W) -> Result<Value>,
{
    let mut initial = initial;
    require(initial.is_object(), "Invalid recovery request.")?;
    let stream = initial.as_object_mut().unwrap().remove("_stream");
    if let Some(stream) = &stream {
        require(stream.is_boolean(), "Invalid recovery stream flag.")?;
    }
    if stream == Some(value!(true)) {
        emit(output, &value!({"authenticated":true}))?;
    }
    if initial["action"] != "browse_session" {
        let result = executor(&initial, output)?;
        emit(output, &result)?;
        return Ok(());
    }
    json::fields(&initial, "action")?;
    while let Some(bytes) = read_line(input)? {
        let mut action = String::new();
        let result = (|| {
            let request = json::decode(&bytes, MAX_REQUEST)?;
            action = browse_action(&request)?.into();
            executor(&request, output)
        })();
        let response = match result {
            Ok(result) => value!({"action":action,"result":result}),
            Err(error) => {
                value!({"action":action,"error":error.to_string().chars().take(500).collect::<String>()})
            }
        };
        emit(output, &response)?;
    }
    Ok(())
}
