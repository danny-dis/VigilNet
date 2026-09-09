//! VigilNet Procedural Macros
//!
//! Provides compile-time code generation for instrumentation and metrics.
//!
//! # Macros
//!
//! - `#[timed]` - Automatically time function execution
//!
//! # Example
//!
//! ```rust
//! use vigilnet_macros::timed;
//!
//! #[timed("process_request_duration")]
//! fn process_request(data: &[u8]) -> Vec<u8> {
//!     // Function body
//!     data.to_vec()
//! }
//!
//! #[timed]
//! async fn async_operation() -> Result<(), ()> {
//!     // Async function body
//!     Ok(())
//! }
//! ```

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::{format_ident, quote};
use syn::{parse_macro_input, AttributeArgs, ItemFn, Lit, Meta, NestedMeta};

/// Attribute macro for timing function execution
///
/// Automatically instruments a function to record its execution time
/// to a histogram metric. The metric name can be specified as an argument
/// or will be derived from the function name.
///
/// # Arguments
///
/// * `metric_name` - Optional custom metric name (default: `{function_name}_duration_seconds`)
///
/// # Examples
///
/// ```rust
/// use vigilnet_macros::timed;
///
/// // With custom metric name
/// #[timed("custom_operation_duration")]
/// fn custom_operation() {
///     // ... work
/// }
///
/// // With derived metric name (process_data_duration_seconds)
/// #[timed]
/// fn process_data() {
///     // ... work
/// }
///
/// // Async functions are also supported
/// #[timed("async_operation_duration")]
/// async fn async_operation() -> Result<(), Error> {
///     // ... async work
///     Ok(())
/// }
/// ```
#[proc_macro_attribute]
pub fn timed(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as AttributeArgs);
    let input_fn = parse_macro_input!(input as ItemFn);

    let ItemFn {
        attrs,
        vis,
        sig,
        block,
    } = input_fn;

    let fn_name = &sig.ident;
    let metric_name = if args.is_empty() {
        // Derive metric name from function name
        format!("{}_duration_seconds", fn_name)
    } else {
        // Use provided metric name
        match &args[0] {
            NestedMeta::Lit(Lit::Str(s)) => s.value(),
            _ => {
                return syn::Error::new(
                    Span::call_site(),
                    "Expected string literal for metric name",
                )
                .to_compile_error()
                .into();
            }
        }
    };

    let metric_name_lit = syn::LitStr::new(&metric_name, Span::call_site());
    let timer_var = format_ident!("__vigilnet_timer_{}", fn_name);

    let is_async = sig.asyncness.is_some();
    let output = if is_async {
        // Async function instrumentation
        quote! {
            #(#attrs)*
            #vis #sig {
                let #timer_var = ::vigilnet_core::instrumentation::ScopedTimer::new(#metric_name_lit);
                async move {
                    let result = #block;
                    drop(#timer_var);
                    result
                }.await
            }
        }
    } else {
        // Sync function instrumentation
        quote! {
            #(#attrs)*
            #vis #sig {
                let #timer_var = ::vigilnet_core::instrumentation::ScopedTimer::new(#metric_name_lit);
                let result = #block;
                drop(#timer_var);
                result
            }
        }
    };

    output.into()
}

/// Attribute macro for counting function calls
///
/// Automatically increments a counter each time the function is called.
///
/// # Arguments
///
/// * `counter_name` - Optional custom counter name (default: `{function_name}_calls_total`)
///
/// # Examples
///
/// ```rust
/// use vigilnet_macros::counted;
///
/// #[counted("requests_total")]
/// fn handle_request() {
///     // ... handle request
/// }
///
/// #[counted]  // Uses handle_event_calls_total
/// fn handle_event() {
///     // ... handle event
/// }
/// ```
#[proc_macro_attribute]
pub fn counted(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as AttributeArgs);
    let input_fn = parse_macro_input!(input as ItemFn);

    let ItemFn {
        attrs,
        vis,
        sig,
        block,
    } = input_fn;

    let fn_name = &sig.ident;
    let counter_name = if args.is_empty() {
        format!("{}_calls_total", fn_name)
    } else {
        match &args[0] {
            NestedMeta::Lit(Lit::Str(s)) => s.value(),
            _ => {
                return syn::Error::new(
                    Span::call_site(),
                    "Expected string literal for counter name",
                )
                .to_compile_error()
                .into();
            }
        }
    };

    let counter_name_lit = syn::LitStr::new(&counter_name, Span::call_site());

    let output = quote! {
        #(#attrs)*
        #vis #sig {
            ::vigilnet_core::instrumentation::counter!(#counter_name_lit).increment(1);
            #block
        }
    };

    output.into()
}

/// Attribute macro for comprehensive function instrumentation
///
/// Combines timing and counting in a single macro. Records both
/// execution time and call count.
///
/// # Arguments
///
/// * `base_name` - Base name for metrics (default: function name)
///   - Counter: `{base_name}_calls_total`
///   - Timer: `{base_name}_duration_seconds`
///
/// # Examples
///
/// ```rust
/// use vigilnet_macros::instrument;
///
/// #[instrument("api_request")]
/// fn handle_api_request() {
///     // Records: api_request_calls_total, api_request_duration_seconds
/// }
/// ```
#[proc_macro_attribute]
pub fn instrument(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as AttributeArgs);
    let input_fn = parse_macro_input!(input as ItemFn);

    let ItemFn {
        attrs,
        vis,
        sig,
        block,
    } = input_fn;

    let fn_name = &sig.ident;
    let base_name = if args.is_empty() {
        fn_name.to_string()
    } else {
        match &args[0] {
            NestedMeta::Lit(Lit::Str(s)) => s.value(),
            _ => {
                return syn::Error::new(
                    Span::call_site(),
                    "Expected string literal for base metric name",
                )
                .to_compile_error()
                .into();
            }
        }
    };

    let counter_name = format!("{}_calls_total", base_name);
    let timer_name = format!("{}_duration_seconds", base_name);

    let counter_name_lit = syn::LitStr::new(&counter_name, Span::call_site());
    let timer_name_lit = syn::LitStr::new(&timer_name, Span::call_site());
    let timer_var = format_ident!("__vigilnet_instrument_timer_{}", fn_name);

    let is_async = sig.asyncness.is_some();
    let output = if is_async {
        quote! {
            #(#attrs)*
            #vis #sig {
                ::vigilnet_core::instrumentation::counter!(#counter_name_lit).increment(1);
                let #timer_var = ::vigilnet_core::instrumentation::ScopedTimer::new(#timer_name_lit);
                async move {
                    let result = #block;
                    drop(#timer_var);
                    result
                }.await
            }
        }
    } else {
        quote! {
            #(#attrs)*
            #vis #sig {
                ::vigilnet_core::instrumentation::counter!(#counter_name_lit).increment(1);
                let #timer_var = ::vigilnet_core::instrumentation::ScopedTimer::new(#timer_name_lit);
                let result = #block;
                drop(#timer_var);
                result
            }
        }
    };

    output.into()
}

/// Derive macro for metrics registration
///
/// Automatically implements the MetricsEnabled trait for a struct,
/// enabling it to expose custom metrics.
///
/// # Example
///
/// ```rust
/// use vigilnet_macros::MetricsEnabled;
///
/// #[derive(MetricsEnabled)]
/// struct MyComponent {
///     // ... fields
/// }
/// ```
#[proc_macro_derive(MetricsEnabled)]
pub fn derive_metrics_enabled(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as syn::DeriveInput);
    let name = &ast.ident;

    let output = quote! {
        impl ::vigilnet_core::metrics::MetricsEnabled for #name {
            fn register_metrics(&self, registry: &::vigilnet_core::metrics::Metrics) {
                // Default implementation - can be overridden
            }
        }
    };

    output.into()
}
