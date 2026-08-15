pub(crate) fn origin_path_is_normalized(path: &str) -> bool {
    if !path.starts_with('/')
        || path.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
        || path.contains(['\\', '%', '#', '?'])
    {
        return false;
    }
    let segments: Vec<_> = path.split('/').collect();
    segments.first() == Some(&"")
        && !segments.iter().enumerate().any(|(index, segment)| {
            *segment == "."
                || *segment == ".."
                || (segment.is_empty()
                    && segments.len() > 2
                    && index != 0
                    && index + 1 != segments.len())
        })
}

pub(crate) fn query_is_safe(query: &str) -> bool {
    !query
        .bytes()
        .any(|byte| byte < 0x20 || byte == 0x7f || byte == b'#')
}
