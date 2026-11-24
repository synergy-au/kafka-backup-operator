//! Topic configuration parser
//!
//! Utilities for parsing topic configuration from Kubernetes ConfigMaps.

use k8s_openapi::api::core::v1::ConfigMap;

use crate::error::{Error, Result};

pub(super) fn config_map_list(
    config: &ConfigMap,
    namespace: &str,
    name: &str,
    key: &str,
) -> Result<Vec<String>> {
    let Some(value) = config.data.as_ref().and_then(|data| data.get(key)) else {
        return Ok(Vec::new());
    };

    parse_list(value).map_err(|error| {
        Error::Config(format!(
            "Invalid string list in ConfigMap '{namespace}/{name}' key '{key}': {error}"
        ))
    })
}

fn parse_list(value: &str) -> std::result::Result<Vec<String>, serde_saphyr::Error> {
    let first = value
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#') && *line != "---")
        .unwrap_or_default();
    let is_yaml = first.starts_with('[')
        || first == "-"
        || first
            .strip_prefix('-')
            .is_some_and(|rest| rest.starts_with(char::is_whitespace))
        || first.starts_with("--- ");

    let items = if is_yaml {
        let mut options: serde_saphyr::Options = Default::default();
        options.no_schema = true;
        options.strict_booleans = true;
        options.with_snippet = false;
        serde_saphyr::from_str_with_options::<Vec<String>>(value, options)?
    } else {
        value.split([',', '\n']).map(str::to_owned).collect()
    };

    Ok(items
        .into_iter()
        .map(|item| item.trim().to_owned())
        .filter(|item| !item.is_empty())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_formats_and_normalizes_blanks() {
        for value in [
            " orders, , events,orders, ",
            " orders\r\n\r\n events\r\norders\r\n",
            " orders,\n events,orders\n",
            "- ' orders '\n- \"\"\n- events\n- orders\n",
            "[orders, '', events, orders]",
            "# topics\n---\n- orders\n- events\n- orders\n",
            "--- [orders, events, orders]",
        ] {
            assert_eq!(parse_list(value).unwrap(), ["orders", "events", "orders"]);
        }
        for value in ["", " \r\n , \n", "[]", "- ''\n- ' '\n"] {
            assert!(parse_list(value).unwrap().is_empty(), "{value:?}");
        }
    }

    #[test]
    fn preserves_literal_patterns_and_mapping_strings() {
        for value in [
            "*,orders-*,orders:restored",
            "*\norders-*\norders:restored",
            "- '*'\n- orders-*\n- orders:restored",
            "['*', orders-*, orders:restored]",
        ] {
            assert_eq!(
                parse_list(value).unwrap(),
                ["*", "orders-*", "orders:restored"]
            );
        }
        assert_eq!(
            parse_list("['orders,events', ' source: target ']").unwrap(),
            ["orders,events", "source: target"]
        );
        assert_eq!(parse_list("-orders").unwrap(), ["-orders"]);
    }

    #[test]
    fn rejects_malformed_yaml_and_non_string_items() {
        for value in [
            "[orders",
            "- orders\n- [broken",
            "- orders: restored",
            "[{orders: restored}]",
            "- [orders]",
            "- 123",
            "- true",
            "- null",
            "-",
            "- orders\n---\n- events",
        ] {
            assert!(parse_list(value).is_err(), "{value:?}");
        }
        assert_eq!(
            parse_list("[\"123\", \"true\", \"null\"]").unwrap(),
            ["123", "true", "null"]
        );
    }
}
