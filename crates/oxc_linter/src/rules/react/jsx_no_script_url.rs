use lazy_regex::{Lazy, Regex, lazy_regex};
use schemars::JsonSchema;
use serde::Deserialize;

use oxc_ast::{AstKind, ast::JSXAttributeItem};
use oxc_diagnostics::OxcDiagnostic;
use oxc_macros::declare_oxc_lint;
use oxc_span::{GetSpan, Span};
use oxc_str::CompactStr;

use crate::{
    AstNode,
    context::{ContextHost, LintContext},
    rule::{MixedTupleRuleConfig, Rule},
};

fn jsx_no_script_url_diagnostic(span: Span) -> OxcDiagnostic {
    OxcDiagnostic::warn("React 19 disallows `javascript:` URLs as a security precaution.")
        .with_help("Use event handlers instead if you can.")
        .with_label(span)
}

static JS_SCRIPT_REGEX: Lazy<Regex> = lazy_regex!(
    r"(j|J)[\r\n\t]*(a|A)[\r\n\t]*(v|V)[\r\n\t]*(a|A)[\r\n\t]*(s|S)[\r\n\t]*(c|C)[\r\n\t]*(r|R)[\r\n\t]*(i|I)[\r\n\t]*(p|P)[\r\n\t]*(t|T)[\r\n\t]*:"
);

#[derive(Debug, Clone)]
pub struct JsxNoScriptUrl(
    Box<MixedTupleRuleConfig<Vec<JsxNoScriptUrlComponent>, JsxNoScriptUrlOptions>>,
);

impl Default for JsxNoScriptUrl {
    fn default() -> Self {
        Self(Box::default())
    }
}

impl std::ops::Deref for JsxNoScriptUrl {
    type Target = MixedTupleRuleConfig<Vec<JsxNoScriptUrlComponent>, JsxNoScriptUrlOptions>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JsxNoScriptUrlComponent {
    /// Component name.
    name: String,
    /// List of properties that should be validated.
    props: Vec<String>,
}

#[derive(Debug, Default, Clone, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct JsxNoScriptUrlOptions {
    /// Whether to include components from settings.
    include_from_settings: bool,
}

declare_oxc_lint!(
    /// ### What it does
    ///
    /// Disallow usage of `javascript:` URLs.
    ///
    /// ### Why is this bad?
    ///
    /// URLs starting with `javascript:` are a dangerous attack surface because it's easy to accidentally
    /// include unsanitized output in a tag like `<a href>` and create a security hole.
    ///
    /// Starting in React 16.9, any URLs starting with `javascript:` log a warning.
    ///
    /// In React 19, `javascript:` URLs are
    /// [disallowed entirely](https://react.dev/blog/2024/04/25/react-19-upgrade-guide#other-breaking-changes).
    ///
    /// ### Examples
    ///
    /// Examples of **incorrect** code for this rule:
    /// ```jsx
    /// <a href="javascript:void(0)">Test</a>
    /// ```
    ///
    /// Examples of **correct** code for this rule:
    /// ```jsx
    /// <Foo test="javascript:void(0)" />
    /// ```
    JsxNoScriptUrl,
    react,
    suspicious,
    pending,
    config = MixedTupleRuleConfig<Vec<JsxNoScriptUrlComponent>, JsxNoScriptUrlOptions>,
    version = "0.13.2",
    short_description = "Disallow usage of `javascript:` URLs.",
);

fn is_link_attribute(tag_name: &str, prop_value_literal: String, ctx: &LintContext) -> bool {
    tag_name == "a"
        || ctx.settings().react.get_link_component_attrs(tag_name).is_some_and(
            |link_component_attrs| {
                link_component_attrs.contains(&CompactStr::from(prop_value_literal))
            },
        )
}

impl JsxNoScriptUrl {
    fn is_link_tag(&self, tag_name: &str, ctx: &LintContext) -> bool {
        if !self.0.1.include_from_settings {
            return tag_name == "a";
        }
        if tag_name == "a" {
            return true;
        }
        ctx.settings().react.get_link_component_attrs(tag_name).is_some()
    }

    fn component_props(&self, component_name: &str) -> Option<&[String]> {
        self.0
            .0
            .iter()
            .find(|component| component.name == component_name)
            .map(|component| component.props.as_slice())
    }
}

impl Rule for JsxNoScriptUrl {
    fn from_configuration(value: serde_json::Value) -> Result<Self, serde_json::error::Error> {
        serde_json::from_value::<
            MixedTupleRuleConfig<Vec<JsxNoScriptUrlComponent>, JsxNoScriptUrlOptions>,
        >(value)
        .map(|config| Self(Box::new(config)))
    }

    fn run<'a>(&self, node: &AstNode<'a>, ctx: &LintContext<'a>) {
        if let AstKind::JSXOpeningElement(element) = node.kind() {
            let Some(component_name) = element.name.get_identifier_name() else {
                return;
            };
            if let Some(link_props) = self.component_props(component_name.as_str()) {
                for jsx_attribute in &element.attributes {
                    if let JSXAttributeItem::Attribute(attr) = jsx_attribute {
                        let Some(prop_value) = &attr.value else {
                            return;
                        };
                        if prop_value.as_string_literal().is_some_and(|val| {
                            link_props.contains(&attr.name.get_identifier().name.to_string())
                                && JS_SCRIPT_REGEX.captures(&val.value).is_some()
                        }) {
                            ctx.diagnostic(jsx_no_script_url_diagnostic(attr.span()));
                        }
                    }
                }
            } else if self.is_link_tag(component_name.as_str(), ctx) {
                for jsx_attribute in &element.attributes {
                    if let JSXAttributeItem::Attribute(attr) = jsx_attribute {
                        let Some(prop_value) = &attr.value else {
                            return;
                        };
                        if prop_value.as_string_literal().is_some_and(|val| {
                            is_link_attribute(
                                component_name.as_str(),
                                attr.name.get_identifier().name.to_string(),
                                ctx,
                            ) && JS_SCRIPT_REGEX.captures(&val.value).is_some()
                        }) {
                            ctx.diagnostic(jsx_no_script_url_diagnostic(attr.span()));
                        }
                    }
                }
            }
        }
    }

    fn should_run(&self, ctx: &ContextHost) -> bool {
        ctx.source_type().is_jsx()
    }
}

#[test]
fn test() {
    use crate::tester::Tester;

    let pass = vec![
        (r#"<a href="https://reactjs.org"></a>"#, None, None),
        (r#"<a href="mailto:foo@bar.com"></a>"#, None, None),
        (r##"<a href="#"></a>"##, None, None),
        (r#"<a href=""></a>"#, None, None),
        (r#"<a name="foo"></a>"#, None, None),
        (r#"<a href={"javascript:"}></a>"#, None, None),
        (r#"<Foo href="javascript:"></Foo>"#, None, None),
        ("<a href />", None, None),
        (
            r#"<Foo other="javascript:"></Foo>"#,
            Some(serde_json::json!([ [{ "name": "Foo", "props": ["to", "href"] }] ])),
            None,
        ),
        (
            r#"<Foo href="javascript:"></Foo>"#,
            None,
            Some(
                serde_json::json!({ "settings": {"react": {"linkComponents": [{ "name": "Foo", "linkAttribute": ["to", "href"] }]} } }),
            ),
        ),
        (
            r#"<Foo other="javascript:"></Foo>"#,
            Some(serde_json::json!([[], { "includeFromSettings": true }])),
            Some(
                serde_json::json!({ "settings": {"react": {"linkComponents": [{ "name": "Foo", "linkAttribute": ["to", "href"] }]} } }),
            ),
        ),
        (
            r#"<Foo href="javascript:"></Foo>"#,
            Some(serde_json::json!([[], { "includeFromSettings": false }])),
            Some(
                serde_json::json!({ "settings": {"react": {"linkComponents": [{ "name": "Foo", "linkAttribute": ["to", "href"] }]} } }),
            ),
        ),
    ];

    let fail = vec![
        (r#"<a href="javascript:"></a>"#, None, None),
        (r#"<a href="javascript:void(0)"></a>"#, None, None),
        (
            r#"<a href="j


			a
v	ascript:"></a>"#,
            None,
            None,
        ),
        (
            r#"<Foo to="javascript:"></Foo>"#,
            Some(serde_json::json!([ [{ "name": "Foo", "props": ["to", "href"] }] ])),
            None,
        ),
        (
            r#"<Foo href="javascript:"></Foo>"#,
            Some(serde_json::json!([ [{ "name": "Foo", "props": ["to", "href"] }] ])),
            None,
        ),
        (
            r#"<a href="javascript:void(0)"></a>"#,
            Some(serde_json::json!([ [{ "name": "Foo", "props": ["to", "href"] }] ])),
            None,
        ),
        (
            r#"<Foo to="javascript:"></Foo>"#,
            Some(
                serde_json::json!([ [{ "name": "Bar", "props": ["to", "href"] }], { "includeFromSettings": true } ]),
            ),
            Some(
                serde_json::json!({ "settings": {"react": {"linkComponents": [{ "name": "Foo", "linkAttribute": "to" }]}}}),
            ),
        ),
        (
            r#"<Foo href="javascript:"></Foo>"#,
            Some(serde_json::json!([{ "includeFromSettings": true }])),
            Some(
                serde_json::json!({ "settings": {"react": {"linkComponents": [{ "name": "Foo", "linkAttribute": ["to", "href"] }]} }}),
            ),
        ),
        (
            r#"
			      <div>
			        <Foo href="javascript:"></Foo>
			        <Bar link="javascript:"></Bar>
			      </div>
			    "#,
            Some(
                serde_json::json!([ [{ "name": "Bar", "props": ["link"] }], { "includeFromSettings": true } ]),
            ),
            Some(
                serde_json::json!({ "settings": {"react": {"linkComponents": [{ "name": "Foo", "linkAttribute": ["to", "href"] }]}} }),
            ),
        ),
        (
            r#"
			      <div>
			        <Foo href="javascript:"></Foo>
			        <Bar link="javascript:"></Bar>
			      </div>
			    "#,
            Some(serde_json::json!([ [{ "name": "Bar", "props": ["link"] }] ])),
            Some(
                serde_json::json!({ "settings": {"react": {"linkComponents": [{ "name": "Foo", "linkAttribute": ["to", "href"] }]}} }),
            ),
        ),
    ];

    Tester::new(JsxNoScriptUrl::NAME, JsxNoScriptUrl::PLUGIN, pass, fail).test_and_snapshot();
}

#[test]
fn invalid_configs_error_in_from_configuration() {
    let unknown_field = serde_json::json!([{ "includeFromSettings": true, "unknown": true }]);
    assert!(JsxNoScriptUrl::from_configuration(unknown_field).is_err());

    let unknown_component_field =
        serde_json::json!([[{ "name": "Foo", "props": ["href"], "extra": true }]]);
    assert!(JsxNoScriptUrl::from_configuration(unknown_component_field).is_err());

    let wrong_type = serde_json::json!([{ "includeFromSettings": "yes" }]);
    assert!(JsxNoScriptUrl::from_configuration(wrong_type).is_err());

    let valid_components = serde_json::json!([[{ "name": "Foo", "props": ["href"] }]]);
    assert!(JsxNoScriptUrl::from_configuration(valid_components).is_ok());

    let valid_options = serde_json::json!([{ "includeFromSettings": true }]);
    assert!(JsxNoScriptUrl::from_configuration(valid_options).is_ok());
}
