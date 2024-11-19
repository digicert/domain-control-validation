package com.digicert.validation.client.dns;

import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DnsType;
import org.xbill.DNS.Record;

import java.util.List;
import java.util.Set;

/**
 * DnsData is a record that encapsulates the results of a DNS query.
 * <p>
 * This record is designed to hold comprehensive information about a DNS query operation. It includes details about the
 * DNS servers that were queried, the domain name that was the subject of the query, the type of DNS record that was
 * requested, the actual DNS records that were retrieved, any errors that were encountered during the query process, and
 * the specific DNS server that provided the data. This encapsulation allows for easy management and access to all
 * relevant data pertaining to a DNS query.
 *
 * @param servers        The list of DNS servers queried.
 *                       <p>
 *                       This parameter holds the list of DNS servers that were contacted during the query process.
 *
 * @param domain         The domain name that was queried.
 *                       <p>
 *                       This parameter specifies the domain name that was the target of the DNS query. It
 *                       is used in conjunction with the DNS record type to form the complete query.
 *
 * @param dnsType        The type of DNS record queried.
 *                       <p>
 *                       This parameter indicates the type of DNS record that was requested, such as A, CNAME, TXT, etc.
 *
 * @param records        The list of DNS records retrieved.
 *                       <p>
 *                       This parameter contains the actual DNS records that were returned in response to the query. These
 *                       records provide the requested information and are the primary result of the DNS query operation.
 *
 * @param errors         The list of errors encountered during the DNS query.
 *                       <p>
 *                       This can be any of the {@link DcvError} values, but will generally be limited to DNS_LOOKUP* errors.
 *
 * @param serverWithData The DNS server that provided the data.
 *                       <p>
 *                       This parameter identifies the specific DNS server that ultimately provided the data for the
 *                       query.
 */
public record DnsData(List<String> servers,
                      String domain,
                      DnsType dnsType,
                      List<Record> records,
                      Set<DcvError> errors,
                      String serverWithData) {
}