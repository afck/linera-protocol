// Copyright (c) Zefchain Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod util;

extern crate proc_macro;
extern crate syn;
use crate::util::{concat, create_entry_name, snakify};
use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote};
use syn::{parse_macro_input, Field, GenericArgument, ItemStruct, PathArguments, Type, TypePath};

fn get_seq_parameter(generics: syn::Generics) -> Vec<syn::Ident> {
    let mut generic_vect = Vec::new();
    for param in generics.params {
        if let syn::GenericParam::Type(param) = param {
            generic_vect.push(param.ident);
        }
    }
    generic_vect
}

fn get_type_field(field: syn::Field) -> Option<syn::Ident> {
    match field.ty {
        syn::Type::Path(typepath) => {
            if let Some(x) = typepath.path.segments.into_iter().next() {
                return Some(x.ident);
            }
            None
        }
        _ => None,
    }
}

fn generate_view_code(input: ItemStruct, root: bool) -> TokenStream2 {
    let struct_name = input.ident;
    let generics = input.generics;
    let template_vect = get_seq_parameter(generics.clone());
    let first_generic = template_vect
        .get(0)
        .expect("failed to find the first generic parameter");

    let mut name_quotes = Vec::new();
    let mut load_future_quotes = Vec::new();
    let mut load_ident_quotes = Vec::new();
    let mut load_result_quotes = Vec::new();
    let mut rollback_quotes = Vec::new();
    let mut flush_quotes = Vec::new();
    let mut delete_quotes = Vec::new();
    let mut clear_quotes = Vec::new();
    for (idx, e) in input.fields.into_iter().enumerate() {
        let name = e.clone().ident.unwrap();
        let fut = format_ident!("{}_fut", name.to_string());
        let idx_lit = syn::LitInt::new(&idx.to_string(), Span::call_site());
        let type_ident = get_type_field(e).expect("Failed to find the type");
        load_future_quotes.push(quote! {
            let index = #idx_lit;
            let base_key = context.derive_key(&index)?;
            let #fut = #type_ident::load(context.clone_with_base_key(base_key));
        });
        load_ident_quotes.push(quote! {
            #fut
        });
        load_result_quotes.push(quote! {
            let #name = result.#idx_lit?;
        });
        name_quotes.push(quote! { #name });
        rollback_quotes.push(quote! { self.#name.rollback(); });
        flush_quotes.push(quote! { self.#name.flush(batch)?; });
        delete_quotes.push(quote! { self.#name.delete(batch); });
        clear_quotes.push(quote! { self.#name.clear(); });
    }
    let first_name_quote = name_quotes
        .get(0)
        .expect("list of names should be non-empty");

    let increment_counter = if root {
        quote! {
            linera_views::increment_counter(
                linera_views::LOAD_VIEW_COUNTER,
                stringify!(#struct_name),
                &context.base_key(),
            );
        }
    } else {
        quote! {}
    };

    quote! {
        #[async_trait::async_trait]
        impl #generics linera_views::views::View<#first_generic> for #struct_name #generics
        where
            #first_generic: Context + Send + Sync + Clone + 'static,
            linera_views::views::ViewError: From<#first_generic::Error>,
        {
            fn context(&self) -> &#first_generic {
                self.#first_name_quote.context()
            }

            async fn load(context: #first_generic) -> Result<Self, linera_views::views::ViewError> {
                #increment_counter
                use linera_views::futures::join;
                #(#load_future_quotes)*
                let result = join!(#(#load_ident_quotes),*);
                #(#load_result_quotes)*
                Ok(Self {#(#name_quotes),*})
            }


            fn rollback(&mut self) {
                #(#rollback_quotes)*
            }

            fn flush(&mut self, batch: &mut linera_views::batch::Batch) -> Result<(), linera_views::views::ViewError> {
                #(#flush_quotes)*
                Ok(())
            }

            fn delete(self, batch: &mut linera_views::batch::Batch) {
                #(#delete_quotes)*
            }

            fn clear(&mut self) {
                #(#clear_quotes)*
            }
        }
    }
}

fn generate_save_delete_view_code(input: ItemStruct) -> TokenStream2 {
    let struct_name = input.ident;
    let generics = input.generics;
    let template_vect = get_seq_parameter(generics.clone());
    let first_generic = template_vect
        .get(0)
        .expect("failed to find the first generic parameter");

    let mut flushes = Vec::new();
    let mut deletes = Vec::new();
    for e in input.fields {
        let name = e.clone().ident.unwrap();
        flushes.push(quote! { self.#name.flush(&mut batch)?; });
        deletes.push(quote! { self.#name.delete(batch); });
    }

    quote! {
        #[async_trait::async_trait]
        impl #generics linera_views::views::RootView<#first_generic> for #struct_name #generics
        where
            #first_generic: Context + Send + Sync + Clone + 'static,
            linera_views::views::ViewError: From<#first_generic::Error>,
        {
            async fn save(&mut self) -> Result<(), linera_views::views::ViewError> {
                linera_views::increment_counter(
                    linera_views::SAVE_VIEW_COUNTER,
                    stringify!(#struct_name),
                    &self.context().base_key(),
                );
                use linera_views::batch::Batch;
                let mut batch = Batch::new();
                #(#flushes)*
                self.context().write_batch(batch).await?;
                Ok(())
            }

            async fn write_delete(self) -> Result<(), linera_views::views::ViewError> {
                use linera_views::batch::Batch;
                let context = self.context().clone();
                let batch = Batch::build(move |batch| {
                    Box::pin(async move {
                        #(#deletes)*
                        Ok(())
                    })
                }).await?;
                context.write_batch(batch).await?;
                Ok(())
            }
        }
    }
}

fn generate_hash_view_code(input: ItemStruct) -> TokenStream2 {
    let struct_name = input.ident;
    let generics = input.generics;
    let template_vect = get_seq_parameter(generics.clone());
    let first_generic = template_vect
        .get(0)
        .expect("failed to find the first generic parameter");

    let mut field_hashes_mut = Vec::new();
    let mut field_hashes = Vec::new();
    for e in input.fields {
        let name = e.clone().ident.unwrap();
        field_hashes_mut.push(quote! { hasher.write_all(self.#name.hash_mut().await?.as_ref())?; });
        field_hashes.push(quote! { hasher.write_all(self.#name.hash().await?.as_ref())?; });
    }

    quote! {
        #[async_trait::async_trait]
        impl #generics linera_views::views::HashableView<#first_generic> for #struct_name #generics
        where
            #first_generic: Context + Send + Sync + Clone + 'static,
            linera_views::views::ViewError: From<#first_generic::Error>,
        {
            type Hasher = linera_views::sha3::Sha3_256;

            async fn hash_mut(&mut self) -> Result<<Self::Hasher as linera_views::views::Hasher>::Output, linera_views::views::ViewError> {
                use linera_views::views::{Hasher, HashableView};
                use std::io::Write;
                let mut hasher = Self::Hasher::default();
                #(#field_hashes_mut)*
                Ok(hasher.finalize())
            }

            async fn hash(&self) -> Result<<Self::Hasher as linera_views::views::Hasher>::Output, linera_views::views::ViewError> {
                use linera_views::views::{Hasher, HashableView};
                use std::io::Write;
                let mut hasher = Self::Hasher::default();
                #(#field_hashes)*
                Ok(hasher.finalize())
            }
        }
    }
}

fn generate_crypto_hash_code(input: ItemStruct) -> TokenStream2 {
    let struct_name = input.ident;
    let generics = input.generics;
    let template_vect = get_seq_parameter(generics.clone());
    let first_generic = template_vect
        .get(0)
        .expect("failed to find the first generic parameter");

    let hash_type = syn::Ident::new(&format!("{}Hash", struct_name), Span::call_site());
    quote! {
        #[async_trait::async_trait]
        impl #generics linera_views::views::CryptoHashView<#first_generic> for #struct_name #generics
        where
            #first_generic: Context + Send + Sync + Clone + 'static,
            linera_views::views::ViewError: From<#first_generic::Error>,
        {
            async fn crypto_hash(&self) -> Result<linera_base::crypto::CryptoHash, linera_views::views::ViewError> {
                use linera_views::generic_array::GenericArray;
                use linera_views::batch::Batch;
                use linera_base::crypto::{BcsHashable, CryptoHash};
                use linera_views::views::HashableView;
                use serde::{Serialize, Deserialize};
                use linera_views::sha3::{Sha3_256, digest::OutputSizeUser};
                #[derive(Serialize, Deserialize)]
                struct #hash_type(GenericArray<u8, <Sha3_256 as OutputSizeUser>::OutputSize>);
                impl BcsHashable for #hash_type {}
                let hash = self.hash().await?;
                Ok(CryptoHash::new(&#hash_type(hash)))
            }
        }
    }
}

fn generic_argument_from_type_path(type_path: &TypePath) -> Vec<&Type> {
    let arguments = &type_path
        .path
        .segments
        .iter()
        .next()
        .expect("type path should have at least one segment")
        .arguments;

    let angle = match arguments {
        PathArguments::AngleBracketed(angle) => angle,
        _ => {
            unreachable!("")
        }
    };

    angle
        .args
        .pairs()
        .map(|pair| *pair.value())
        .map(|value| match value {
            GenericArgument::Type(r#type) => r#type,
            _ => panic!("Only types are supported as generic arguments in views."),
        })
        .collect()
}

fn generate_graphql_code_for_field(field: Field) -> (TokenStream2, Option<TokenStream2>) {
    let field_name = field
        .ident
        .clone()
        .expect("anonymous fields not supported.");
    let view_type = get_type_field(field.clone()).expect("could not get view type.");
    let type_path = match field.ty {
        Type::Path(type_path) => type_path,
        _ => panic!(),
    };

    let view_name = view_type.to_string();
    match view_type.to_string().as_str() {
        "RegisterView" => {
            let generic_arguments = generic_argument_from_type_path(&type_path);
            let generic_ident = generic_arguments
                .get(1)
                .expect("no generic specified for 'RegisterView'");
            let r#impl = quote! {
                async fn #field_name(&self) -> &#generic_ident {
                    self.#field_name.get()
                }
            };
            (r#impl, None)
        }
        "CollectionView" | "CustomCollectionView" => {
            let generic_arguments = generic_argument_from_type_path(&type_path);
            let index_ident = generic_arguments
                .get(1)
                .unwrap_or_else(|| panic!("no index specified for '{}'", view_name));
            let generic_ident = generic_arguments
                .get(2)
                .unwrap_or_else(|| panic!("no generic type specified for '{}'", view_name));

            let index_name = snakify(index_ident);
            let entry_name = create_entry_name(generic_ident);

            let r#impl = quote! {
                async fn #field_name(&self, #index_name: #index_ident) -> Result<#entry_name<C>, async_graphql::Error> {
                    Ok(#entry_name {
                        #index_name: #index_name.clone(),
                        guard: self.#field_name.try_load_entry(&#index_name).await?,
                    })
                }
            };

            let generic_method_name = snakify(generic_ident);

            let r#struct = quote! {
                pub struct #entry_name<'a, C>
                where
                    C: Sync + Send + linera_views::common::Context + 'static,
                    linera_views::views::ViewError: From<C::Error>,
                {
                    #index_name: #index_ident,
                    guard: linera_views::collection_view::ReadGuardedView<'a, #generic_ident>,
                }

                #[async_graphql::Object]
                impl<'a, C> #entry_name<'a, C>
                where
                    C: Sync + Send + linera_views::common::Context + 'static + Clone,
                    linera_views::views::ViewError: From<C::Error>,
                {
                    async fn #index_name(&self) -> &#index_ident {
                        &self.#index_name
                    }

                    async fn #generic_method_name(&self) -> &#generic_ident {
                        use std::ops::Deref;
                        self.guard.deref()
                    }
                }
            };

            (r#impl, Some(r#struct))
        }
        "SetView" | "CustomSetView" => {
            let generic_arguments = generic_argument_from_type_path(&type_path);
            let generic_ident = generic_arguments
                .get(1)
                .unwrap_or_else(|| panic!("no generic type specified for '{}'", view_name));

            let r#impl = quote! {
                async fn #field_name(&self) -> Result<Vec<#generic_ident>, async_graphql::Error> {
                    Ok(self.#field_name.indices().await?)
                }
            };
            (r#impl, None)
        }
        "LogView" => {
            let generic_arguments = generic_argument_from_type_path(&type_path);
            let generic_ident = generic_arguments
                .get(1)
                .expect("no generic type specified for 'LogView'");

            let r#impl = quote! {
                async fn #field_name(&self,
                    start: Option<usize>,
                    end: Option<usize>
                ) -> Result<Vec<#generic_ident>, async_graphql::Error> {
                    let range = std::ops::Range {
                        start: start.unwrap_or(0),
                        end: end.unwrap_or(self.#field_name.count()),
                    };
                    Ok(self.#field_name.read(range).await?)
                }
            };
            (r#impl, None)
        }
        "WrappedHashableContainerView" => {
            let generic_arguments = generic_argument_from_type_path(&type_path);
            let generic_ident = generic_arguments
                .get(1)
                .expect("no generic specified for 'WrappedHashableContainerView'");
            let r#impl = quote! {
                async fn #field_name(&self) -> &#generic_ident {
                    use std::ops::Deref;
                    self.#field_name.deref()
                }
            };
            (r#impl, None)
        }
        "QueueView" => {
            let generic_arguments = generic_argument_from_type_path(&type_path);
            let generic_ident = generic_arguments
                .get(1)
                .expect("no generic type specified for 'QueueView'");

            let r#impl = quote! {
                async fn #field_name(&self, count: Option<usize>) -> Result<Vec<#generic_ident>, async_graphql::Error> {
                    let count = count.unwrap_or_else(|| self.#field_name.count());
                    Ok(self.#field_name.read_front(count).await?)
                }
            };
            (r#impl, None)
        }
        "ByteMapView" => {
            let generic_arguments = generic_argument_from_type_path(&type_path);
            let generic_ident = generic_arguments
                .get(1)
                .expect("no generic type specified for 'ByteMapView'");

            let r#impl = quote! {
                async fn #field_name(&self, short_key: Vec<u8>) -> Result<Option<#generic_ident>, async_graphql::Error> {
                    Ok(self.#field_name.get(&short_key).await?)
                }
            };
            (r#impl, None)
        }
        "MapView" | "CustomMapView" => {
            let generic_arguments = generic_argument_from_type_path(&type_path);
            let index_ident = generic_arguments
                .get(1)
                .unwrap_or_else(|| panic!("no index specified for '{}'", view_name));
            let generic_ident = generic_arguments
                .get(2)
                .unwrap_or_else(|| panic!("no generic type specified for '{}'", view_name));

            let index_name = snakify(index_ident);
            let field_keys = concat(&field_name, "_keys");

            let r#impl = quote! {
                async fn #field_name(&self, #index_name: #index_ident) -> Result<Option<#generic_ident>, async_graphql::Error> {
                    Ok(self.#field_name.get(&#index_name).await?)
                }
                async fn #field_keys(&self, count: Option<u64>)
                    -> Result<Vec<#index_ident>, async_graphql::Error>
                {
                    let count = count.unwrap_or(u64::MAX).try_into().unwrap_or(usize::MAX);
                    let mut keys = vec![];
                    if count == 0 {
                        return Ok(keys);
                    }
                    self.#field_name.for_each_index_while(|key| {
                        keys.push(key);
                        Ok(keys.len() < count)
                    }).await?;
                    Ok(keys)
                }
            };
            (r#impl, None)
        }
        _ => {
            let r#impl = quote! {
                async fn #field_name(&self) -> &#type_path {
                    &self.#field_name
                }
            };
            (r#impl, None)
        }
    }
}

fn generate_graphql_code(input: ItemStruct) -> TokenStream2 {
    let struct_name = input.ident;
    let generics = input.generics;
    let template_vect = get_seq_parameter(generics.clone());
    let first_generic = template_vect
        .get(0)
        .expect("failed to find the first generic parameter");

    let mut impls = vec![];
    let mut structs = vec![];

    for field in input.fields {
        let (r#impl, r#struct) = generate_graphql_code_for_field(field);
        impls.push(r#impl);
        if let Some(r#struct) = r#struct {
            structs.push(r#struct);
        }
    }

    quote! {
        #(#structs)*

        #[async_graphql::Object]
        impl #generics #struct_name #generics
        where
            #first_generic: linera_views::common::Context + Send + Sync + Clone + 'static,
            linera_views::views::ViewError: From<#first_generic::Error>,
        {
            #

            (#impls)

            *
        }
    }
}

#[proc_macro_derive(View)]
pub fn derive_view(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as ItemStruct);
    generate_view_code(input, false).into()
}

#[proc_macro_derive(HashableView)]
pub fn derive_hash_view(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as ItemStruct);
    let mut stream = generate_view_code(input.clone(), false);
    stream.extend(generate_hash_view_code(input));
    stream.into()
}

#[proc_macro_derive(RootView)]
pub fn derive_root_view(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as ItemStruct);
    let mut stream = generate_view_code(input.clone(), true);
    stream.extend(generate_save_delete_view_code(input));
    stream.into()
}

#[proc_macro_derive(CryptoHashView)]
pub fn derive_crypto_hash_view(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as ItemStruct);
    let mut stream = generate_view_code(input.clone(), false);
    stream.extend(generate_hash_view_code(input.clone()));
    stream.extend(generate_crypto_hash_code(input));
    stream.into()
}

#[proc_macro_derive(CryptoHashRootView)]
pub fn derive_crypto_hash_root_view(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as ItemStruct);
    let mut stream = generate_view_code(input.clone(), true);
    stream.extend(generate_save_delete_view_code(input.clone()));
    stream.extend(generate_hash_view_code(input.clone()));
    stream.extend(generate_crypto_hash_code(input));
    stream.into()
}

#[proc_macro_derive(HashableRootView)]
#[cfg(test)]
pub fn derive_hashable_root_view(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as ItemStruct);
    let mut stream = generate_view_code(input.clone(), true);
    stream.extend(generate_save_delete_view_code(input.clone()));
    stream.extend(generate_hash_view_code(input));
    stream.into()
}

#[proc_macro_derive(GraphQLView)]
pub fn derive_graphql_view(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as ItemStruct);
    generate_graphql_code(input).into()
}

#[cfg(test)]
pub mod tests {

    use crate::*;
    use quote::quote;
    use syn::parse_quote;

    fn assert_eq_no_whitespace(mut actual: String, mut expected: String) {
        // Intentionally left here for debugging purposes
        println!("{}", actual);

        actual.retain(|c| !c.is_whitespace());
        expected.retain(|c| !c.is_whitespace());

        assert_eq!(actual, expected);
    }

    #[test]
    #[rustfmt::skip]
    fn test_generate_view_code() {
        let input: ItemStruct = parse_quote!(
            struct TestView<C> {
                register: RegisterView<C, usize>,
                collection: CollectionView<C, usize, RegisterView<C, usize>>,
            }
        );
        let output = generate_view_code(input, true);

        let expected = quote!(
            #[async_trait::async_trait]
            impl<C> linera_views::views::View<C> for TestView<C>
            where
                C: Context + Send + Sync + Clone + 'static,
                linera_views::views::ViewError: From<C::Error>,
            {
                fn context(&self) -> &C {
                    self.register.context()
                }
                async fn load(context: C) -> Result<Self, linera_views::views::ViewError> {
                    linera_views::increment_counter(
                        linera_views::LOAD_VIEW_COUNTER,
                        stringify!(TestView),
                        &context.base_key(),
                    );
                    use linera_views::futures::join;
                    let index = 0;
                    let base_key = context.derive_key(&index)?;
                    let register_fut =
                        RegisterView::load(context.clone_with_base_key(base_key));
                    let index = 1;
                    let base_key = context.derive_key(&index)?;
                    let collection_fut =
                        CollectionView::load(context.clone_with_base_key(base_key));
                    let result = join!(register_fut, collection_fut);
                    let register = result.0?;
                    let collection = result.1?;
                    Ok(Self {
                        register,
                        collection
                    })
                }
                fn rollback(&mut self) {
                    self.register.rollback();
                    self.collection.rollback();
                }
                fn flush(
                    &mut self,
                    batch: &mut linera_views::batch::Batch
                ) -> Result<(), linera_views::views::ViewError> {
                    self.register.flush(batch)?;
                    self.collection.flush(batch)?;
                    Ok(())
                }
                fn delete(self, batch: &mut linera_views::batch::Batch) {
                    self.register.delete(batch);
                    self.collection.delete(batch);
                }
                fn clear(&mut self) {
                    self.register.clear();
                    self.collection.clear();
                }
            }
        );

        assert_eq!(output.to_string(), expected.to_string());
    }

    #[test]
    #[rustfmt::skip]
    fn test_generate_hash_view_code() {
        let input: ItemStruct = parse_quote!(
            struct TestView<C> {
                register: RegisterView<C, usize>,
                collection: CollectionView<C, usize, RegisterView<C, usize>>,
            }
        );
        let output = generate_hash_view_code(input);

        let expected = quote!(
            #[async_trait::async_trait]
            impl<C> linera_views::views::HashableView<C> for TestView<C>
            where
                C: Context + Send + Sync + Clone + 'static,
                linera_views::views::ViewError: From<C::Error>,
            {
                type Hasher = linera_views::sha3::Sha3_256;
                async fn hash_mut(
                    &mut self
                ) -> Result<<Self::Hasher as linera_views::views::Hasher>::Output,
                    linera_views::views::ViewError
                > {
                    use linera_views::views::{Hasher, HashableView};
                    use std::io::Write;
                    let mut hasher = Self::Hasher::default();
                    hasher.write_all(self.register.hash_mut().await?.as_ref())?;
                    hasher.write_all(self.collection.hash_mut().await?.as_ref())?;
                    Ok(hasher.finalize())
                }
                async fn hash(
                    &self
                ) -> Result<<Self::Hasher as linera_views::views::Hasher>::Output,
                    linera_views::views::ViewError
                > {
                    use linera_views::views::{Hasher, HashableView};
                    use std::io::Write;
                    let mut hasher = Self::Hasher::default();
                    hasher.write_all(self.register.hash().await?.as_ref())?;
                    hasher.write_all(self.collection.hash().await?.as_ref())?;
                    Ok(hasher.finalize())
                }
            }
        );

        assert_eq!(output.to_string(), expected.to_string());
    }

    #[test]
    #[rustfmt::skip]
    fn test_generate_save_delete_view_code() {
        let input: ItemStruct = parse_quote!(
            struct TestView<C> {
                register: RegisterView<C, usize>,
                collection: CollectionView<C, usize, RegisterView<C, usize>>,
            }
        );
        let output = generate_save_delete_view_code(input);

        let expected = quote!(
            #[async_trait::async_trait]
            impl<C> linera_views::views::RootView<C> for TestView<C>
            where
                C: Context + Send + Sync + Clone + 'static,
                linera_views::views::ViewError: From<C::Error>,
            {
                async fn save(&mut self) -> Result<(), linera_views::views::ViewError> {
                    linera_views::increment_counter(
                        linera_views::SAVE_VIEW_COUNTER,
                        stringify!(TestView),
                        &self.context().base_key(),
                    );
                    use linera_views::batch::Batch;
                    let mut batch = Batch::new();
                    self.register.flush(&mut batch)?;
                    self.collection.flush(&mut batch)?;
                    self.context().write_batch(batch).await?;
                    Ok(())
                }
                async fn write_delete(self) -> Result<(), linera_views::views::ViewError> {
                    use linera_views::batch::Batch;
                    let context = self.context().clone();
                    let batch = Batch::build(move |batch| {
                        Box::pin(async move {
                            self.register.delete(batch);
                            self.collection.delete(batch);
                            Ok(())
                        })
                    })
                    .await?;
                    context.write_batch(batch).await?;
                    Ok(())
                }
            }
        );

        assert_eq!(output.to_string(), expected.to_string());
    }

    #[test]
    #[rustfmt::skip]
    fn test_generate_crypto_hash_code() {
        let input: ItemStruct = parse_quote!(
            struct TestView<C> {
                register: RegisterView<C, usize>,
                collection: CollectionView<C, usize, RegisterView<C, usize>>,
            }
        );
        let output = generate_crypto_hash_code(input);

        let expected = quote!(
            #[async_trait::async_trait]
            impl<C> linera_views::views::CryptoHashView<C> for TestView<C>
            where
                C: Context + Send + Sync + Clone + 'static,
                linera_views::views::ViewError: From<C::Error>,
            {
                async fn crypto_hash(
                    &self
                ) -> Result<linera_base::crypto::CryptoHash, linera_views::views::ViewError>
                {
                    use linera_views::generic_array::GenericArray;
                    use linera_views::batch::Batch;
                    use linera_base::crypto::{BcsHashable, CryptoHash};
                    use linera_views::views::HashableView;
                    use serde::{Serialize, Deserialize};
                    use linera_views::sha3::{Sha3_256, digest::OutputSizeUser};
                    #[derive(Serialize, Deserialize)]
                    struct TestViewHash(GenericArray<u8, <Sha3_256 as OutputSizeUser>::OutputSize>);
                    impl BcsHashable for TestViewHash {}
                    let hash = self.hash().await?;
                    Ok(CryptoHash::new(&TestViewHash(hash)))
                }
            }
        );

        assert_eq!(output.to_string(), expected.to_string());
    }

    #[test]
    #[rustfmt::skip]
    fn test_generate_graphql_code() {
        let input: ItemStruct = parse_quote!(
            struct TestView<C> {
                raw: String,
                register: RegisterView<C, Option<usize>>,
                collection: CollectionView<C, String, SomeOtherView<C>>,
                set: SetView<C, HashSet<usize>>,
                log: LogView<C, usize>,
                queue: QueueView<C, usize>,
                map: MapView<C, String, usize>
            }
        );

        let output = generate_graphql_code(input);

        let expected = quote!(
            pub struct SomeOtherViewEntry<'a, C>
                where
                    C: Sync + Send + linera_views::common::Context + 'static,
                    linera_views::views::ViewError: From<C::Error>,
            {
                string: String,
                guard: linera_views::collection_view::ReadGuardedView<'a, SomeOtherView<C>>,
            }
            #[async_graphql::Object]
            impl<'a, C> SomeOtherViewEntry<'a, C>
                where
                    C: Sync + Send + linera_views::common::Context + 'static + Clone,
                    linera_views::views::ViewError: From<C::Error>,
            {
                async fn string(&self) -> &String {
                    &self.string
                }
                async fn some_other_view(&self) -> &SomeOtherView<C> {
                    use std::ops::Deref;
                    self.guard.deref()
                }
            }
            #[async_graphql::Object]
            impl<C> TestView<C>
                where
                    C: linera_views::common::Context + Send + Sync + Clone + 'static,
                    linera_views::views::ViewError: From<C::Error>,
            {
                async fn raw(&self) -> &String {
                    &self.raw
                }
                async fn register(&self) -> &Option<usize> {
                    self.register.get()
                }
                async fn collection(
                    &self,
                    string: String
                ) -> Result<SomeOtherViewEntry<C>, async_graphql::Error> {
                    Ok(SomeOtherViewEntry {
                        string: string.clone(),
                        guard: self.collection.try_load_entry(&string).await?,
                    })
                }
                async fn set(&self) -> Result<Vec<HashSet<usize>>, async_graphql::Error> {
                    Ok(self.set.indices().await?)
                }
                async fn log(
                    &self,
                    start: Option<usize>,
                    end: Option<usize>
                ) -> Result<Vec<usize>, async_graphql::Error> {
                    let range = std::ops::Range {
                        start: start.unwrap_or(0),
                        end: end.unwrap_or(self.log.count()),
                    };
                    Ok(self.log.read(range).await?)
                }
                async fn queue(&self, count: Option<usize>) -> Result<Vec<usize>, async_graphql::Error> {
                    let count = count.unwrap_or_else(|| self.queue.count());
                    Ok(self.queue.read_front(count).await?)
                }
                async fn map(&self, string: String) -> Result<Option<usize>, async_graphql::Error> {
                    Ok(self.map.get(&string).await?)
                }
                async fn map_keys(&self, count: Option<u64>)
                    -> Result<Vec<String>, async_graphql::Error>
                {
                    let count = count.unwrap_or(u64::MAX).try_into().unwrap_or(usize::MAX);
                    let mut keys = vec![];
                    if count == 0 {
                        return Ok(keys);
                    }
                    self.map.for_each_index_while(|key| {
                        keys.push(key);
                        Ok(keys.len() < count)
                    }).await?;
                    Ok(keys)
                }
            }

        );

        assert_eq_no_whitespace(output.to_string(), expected.to_string())
    }
}
