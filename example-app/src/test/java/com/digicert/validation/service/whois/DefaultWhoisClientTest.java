package com.digicert.validation.service.whois;

import org.apache.commons.net.whois.WhoisClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

class DefaultWhoisClientTest {

    private WhoisClient whoisClient;
    private final String defaultDomain = "markmonitor.com";
    private final String whoisHost = "whoisHost";

    private DefaultWhoisClient defaultWhoisClient;

    @BeforeEach
    public void setUp() {
        whoisClient = mock(WhoisClient.class);

        defaultWhoisClient = new DefaultWhoisClient() {
            @Override
            WhoisClient getWhoisClient() {
                return whoisClient;
            }
        };
    }

    @Test
    void makeWhoIsCall_happyPath() throws IOException {
        doNothing().when(whoisClient).connect(anyString(), anyInt());
        when(whoisClient
                .query(DefaultWhoisClient.USE_LONG_OUTPUT, defaultDomain))
                .thenReturn(WHOIS_RESPONSE);
        doNothing().when(whoisClient).disconnect();

        DefaultWhoisClient.WhoisResponse whoisResponse = defaultWhoisClient.query(defaultDomain, whoisHost);

        assertEquals(WHOIS_RESPONSE,  whoisResponse.response());
    }

    @Test
    void makeWhoIsCall_fingerQuery_throwsException() throws IOException {
        doNothing().when(whoisClient).connect(anyString(), anyInt());
        doThrow(new IOException("TEST Exception - Error querying whois for domain: " + defaultDomain))
                .when(whoisClient).query(DefaultWhoisClient.USE_LONG_OUTPUT, defaultDomain);
        doNothing().when(whoisClient).disconnect();

        DefaultWhoisClient.WhoisResponse whoisResponse = defaultWhoisClient.query(defaultDomain, whoisHost);

        assertEquals("", whoisResponse.response());
    }

    @Test
    void getWhoisEmailContacts_withRedirect_happyPath() throws IOException {
        doNothing().when(whoisClient).connect(anyString(), anyInt());
        when(whoisClient
                .query(DefaultWhoisClient.USE_LONG_OUTPUT, defaultDomain))
                .thenReturn(WHOIS_REDIRECT_RESPONSE)
                .thenReturn(WHOIS_RESPONSE);
        doNothing().when(whoisClient).disconnect();

        WhoisData whoisData = defaultWhoisClient.getWhoisEmailContacts(defaultDomain);

        assertEquals(2, whoisData.emails().size());
        String[] emailsArray = whoisData.emails().toArray(new String[0]);
        assertEquals("custserv2@markmonitor.com", emailsArray[0]);
    }

    @Test
    void getWhoisEmailContrast_withRedirect_toHostAlreadyQueried() throws IOException{
        doNothing().when(whoisClient).connect(anyString(), anyInt());
        when(whoisClient
                .query(DefaultWhoisClient.USE_LONG_OUTPUT, defaultDomain))
                .thenReturn(WHOIS_REDIRECT_RESPONSE);
        doNothing().when(whoisClient).disconnect();

        WhoisData whoisData = defaultWhoisClient.getWhoisEmailContacts(defaultDomain);

        assertEquals(1, whoisData.emails().size());
        String[] emailsArray = whoisData.emails().toArray(new String[0]);
        assertEquals("custserv2@markmonitor.com", emailsArray[0]);
    }

    @Test
    void getWhoisEmailContacts_fingerDisconnect_throwsException() throws IOException {
        doNothing().when(whoisClient).connect(anyString(), anyInt());
        when(whoisClient.isConnected()).thenReturn(true);
        when(whoisClient
                .query(DefaultWhoisClient.USE_LONG_OUTPUT, defaultDomain))
                .thenReturn("");
        doThrow(new IOException("TEST Exception - Error getting whois email contacts for domain: " + defaultDomain))
                .when(whoisClient).disconnect();

        WhoisData whoisData = defaultWhoisClient.getWhoisEmailContacts(defaultDomain);

        assertEquals(0, whoisData.emails().size());
    }

    @Test
    void getMatchedValue_matches(){
        String[] prefixes = {"ONE", "TWO"};
        String line = "TWO value";

        assertEquals("value", defaultWhoisClient.getMatchedValue(prefixes, line));
    }

    @Test
    void extractWhoisRedirectHost_matchingDomain_isNotIPAddress(){
        assertEquals("whois.markmonitor.com", defaultWhoisClient.extractWhoisRedirectHost(WHOIS_REDIRECT_RESPONSE));
    }

    private final static String WHOIS_RESPONSE = """
            Domain Name: markmonitor.com
            Registry Domain ID: 5604337_DOMAIN_COM-VRSN
            Registrar WHOIS Server: whois.markmonitor.com
            Registrar URL: http://www.markmonitor.com
            Updated Date: 2024-08-02T02:17:33+0000
            Creation Date: 1999-04-23T07:00:00+0000
            Registrar Registration Expiration Date: 2032-04-23T00:00:00+0000
            Registrar: MarkMonitor, Inc.
            Registrar IANA ID: 292
            Registrar Abuse Contact Email: abusecomplaints@markmonitor.com
            Registrar Abuse Contact Phone: +1.2086851750
            Domain Status: clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)
            Domain Status: clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)
            Domain Status: clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)
            Domain Status: serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)
            Domain Status: serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)
            Domain Status: serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)
            Registrant Organization: Markmonitor Inc.
            Registrant State/Province: ID
            Registrant Country: US
            Registrant Email: Select Request Email Form at https://domains.markmonitor.com/whois/markmonitor.com
            Registry Admin ID:\s
            Admin Name: MarkMonitor Inc
            Admin Organization: Markmonitor Inc.
            Admin Street: 1120 S. Rackham Way, Suite 300
            Admin City: Meridian
            Admin State/Province: ID
            Admin Postal Code: 83642
            Admin Country: US
            Admin Phone: +1.2083895784
            Admin Phone Ext:\s
            Admin Fax: +1.2083895771
            Admin Fax Ext:\s
            Admin Email: custserv@markmonitor.com
            Registry Tech ID:\s
            Tech Name: MarkMonitor Inc
            Tech Organization: Markmonitor Inc.
            Tech Street: 1120 S. Rackham Way, Suite 300
            Tech City: Meridian
            Tech State/Province: ID
            Tech Postal Code: 83642
            Tech Country: US
            Tech Phone: +1.2083895784
            Tech Phone Ext:\s
            Tech Fax: +1.2083895771
            Tech Fax Ext:\s
            Tech Email: custserv@markmonitor.com
            Name Server: ha2.markmonitor.zone
            Name Server: ha4.markmonitor.zone
            Name Server: ns4.markmonitor.com
            Name Server: ns2.markmonitor.com
            Name Server: ns6.markmonitor.com
            Name Server: ns1.markmonitor.com
            Name Server: ns3.markmonitor.com
            Name Server: ns5.markmonitor.com
            Name Server: ns7.markmonitor.com
            DNSSEC: unsigned
            URL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/
            >>> Last update of WHOIS database: 2024-08-27T21:43:05+0000 <<<
            
            For more information on WHOIS status codes, please visit:
              https://www.icann.org/resources/pages/epp-status-codes
            
            If you wish to contact this domain’s Registrant, Administrative, or Technical
            contact, and such email address is not visible above, you may do so via our web
            form, pursuant to ICANN’s Temporary Specification. To verify that you are not a
            robot, please enter your email address to receive a link to a page that
            facilitates email communication with the relevant contact(s).
            
            Web-based WHOIS:
              https://domains.markmonitor.com/whois
            
            If you have a legitimate interest in viewing the non-public WHOIS details, send
            your request and the reasons for your request to whoisrequest@markmonitor.com
            and specify the domain name in the subject line. We will review that request and
            may ask for supporting documentation and explanation.
            
            The data in MarkMonitor’s WHOIS database is provided for information purposes,
            and to assist persons in obtaining information about or related to a domain
            name’s registration record. While MarkMonitor believes the data to be accurate,
            the data is provided "as is" with no guarantee or warranties regarding its
            accuracy.
            
            By submitting a WHOIS query, you agree that you will use this data only for
            lawful purposes and that, under no circumstances will you use this data to:
              (1) allow, enable, or otherwise support the transmission by email, telephone,
            or facsimile of mass, unsolicited, commercial advertising, or spam; or
              (2) enable high volume, automated, or electronic processes that send queries,
            data, or email to MarkMonitor (or its systems) or the domain name contacts (or
            its systems).
            
            MarkMonitor reserves the right to modify these terms at any time.
            
            By submitting this query, you agree to abide by this policy.
            
            MarkMonitor Domain Management(TM)
            Protecting companies and consumers in a digital world.
            
            Visit MarkMonitor at https://www.markmonitor.com
            Contact us at +1.8007459229
            In Europe, at +44.02032062220
            --
            """;

    private final static String WHOIS_REDIRECT_RESPONSE = """
               Domain Name: MARKMONITOR.COM
               Registry Domain ID: 5604337_DOMAIN_COM-VRSN
               Registrar WHOIS Server: whois.markmonitor.com
               Registrar URL: http://www.markmonitor.com
               Updated Date: 2024-01-18T18:54:43Z
               Creation Date: 1999-04-23T04:00:00Z
               Registry Expiry Date: 2032-04-23T04:00:00Z
               Registrar: MarkMonitor Inc.
               Registrar IANA ID: 292
               Registrar Abuse Contact Email: abusecomplaints@markmonitor.com
               Registrar Abuse Contact Phone: +1.2086851750
               Admin Email: custserv2@markmonitor.com
               Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
               Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
               Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
               Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited
               Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited
               Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited
               Name Server: HA2.MARKMONITOR.ZONE
               Name Server: HA4.MARKMONITOR.ZONE
               Name Server: NS1.MARKMONITOR.COM
               Name Server: NS2.MARKMONITOR.COM
               Name Server: NS3.MARKMONITOR.COM
               Name Server: NS4.MARKMONITOR.COM
               Name Server: NS5.MARKMONITOR.COM
               Name Server: NS6.MARKMONITOR.COM
               Name Server: NS7.MARKMONITOR.COM
               DNSSEC: unsigned
               URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
            >>> Last update of whois database: 2024-08-27T15:14:44Z <<<
            
            For more information on Whois status codes, please visit https://icann.org/epp
            
            NOTICE: The expiration date displayed in this record is the date the
            registrar's sponsorship of the domain name registration in the registry is
            currently set to expire. This date does not necessarily reflect the expiration
            date of the domain name registrant's agreement with the sponsoring
            registrar.  Users may consult the sponsoring registrar's Whois database to
            view the registrar's reported date of expiration for this registration.
            
            TERMS OF USE: You are not authorized to access or query our Whois
            database through the use of electronic processes that are high-volume and
            automated except as reasonably necessary to register domain names or
            modify existing registrations; the Data in VeriSign Global Registry
            Services' ("VeriSign") Whois database is provided by VeriSign for
            information purposes only, and to assist persons in obtaining information
            about or related to a domain name registration record. VeriSign does not
            guarantee its accuracy. By submitting a Whois query, you agree to abide
            by the following terms of use: You agree that you may use this Data only
            for lawful purposes and that under no circumstances will you use this Data
            to: (1) allow, enable, or otherwise support the transmission of mass
            unsolicited, commercial advertising or solicitations via e-mail, telephone,
            or facsimile; or (2) enable high volume, automated, electronic processes
            that apply to VeriSign (or its computer systems). The compilation,
            repackaging, dissemination or other use of this Data is expressly
            prohibited without the prior written consent of VeriSign. You agree not to
            use electronic processes that are automated and high-volume to access or
            query the Whois database except as reasonably necessary to register
            domain names or modify existing registrations. VeriSign reserves the right
            to restrict your access to the Whois database in its sole discretion to ensure
            operational stability.  VeriSign may restrict or terminate your access to the
            Whois database for failure to abide by these terms of use. VeriSign
            reserves the right to modify these terms at any time.
            
            The Registry database contains ONLY .COM, .NET, .EDU domains and
            Registrars.
            """;
}