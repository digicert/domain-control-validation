/*
 * Copyright (C) 2013 The Guava Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package com.digicert.validation.psl;

/**
 * Enum representing the type of public suffix.
 * <p>
 * This enum defines the types of public suffixes that can be encountered. Public suffixes are domain names under which
 * Internet users can directly register names. They are used to determine the boundaries of domain names for various
 * purposes, such as cookie setting and domain name validation. The `PublicSuffixType` enum provides a way to categorize
 * these suffixes based on their characteristics and usage.
 */
public enum PublicSuffixType {

    /**
     * Public suffix that is backed by an ICANN-style domain name registry.
     * <p>
     * The `REGISTRY_ONLY` type represents public suffixes that are managed by official domain name registries, typically
     * under the oversight of the Internet Corporation for Assigned Names and Numbers (ICANN). These suffixes follow
     * strict policies and guidelines for domain name registration and management. Examples include `.com`, `.org`, and
     * country-code top-level domains (ccTLDs) like `.uk` and `.jp`.
     */
    REGISTRY_ONLY(),

    /**
     * Any type of public suffix.
     * <p>
     * The `ANY` type encompasses all kinds of public suffixes, including those managed by ICANN-style registries as well
     * as other types of suffixes that may not follow the same stringent policies. This type is more inclusive and can
     * cover a broader range of domain names, including private or custom suffixes used by organizations for internal
     * purposes. It is useful for applications that need to handle a wide variety of domain name structures.
     */
    ANY()
}
