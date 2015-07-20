/*
 * Copyright 2012, 2014 the original author or authors.
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */

package org.bitcoinj.uri;

import org.coinj.api.CoinDefinition;
import org.coinj.api.CoinLocator;
import org.bitcoinj.core.Address;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;
import com.google.common.collect.ImmutableList;
import org.junit.Test;

import java.io.UnsupportedEncodingException;

import static org.bitcoinj.core.Coin.*;
import static org.junit.Assert.*;

public class BitcoinURITest {
    private CoinURI testObject = null;
    
    private static final String MAINNET_GOOD_ADDRESS = "1KzTSfqjF2iKCduwz59nv2uqh1W2JsTxZH";

    private static final CoinDefinition COIN_DEFINITION = CoinLocator.discoverCoinDefinition();
    private static final String BITCOIN_SCHEME = COIN_DEFINITION.getUriScheme();

    @Test
    public void testConvertToBitcoinURI() throws Exception {
        final CoinDefinition coinDefinition = COIN_DEFINITION;
        Address goodAddress = new Address(MainNetParams.get(coinDefinition), MAINNET_GOOD_ADDRESS);
        
        // simple example
        assertEquals("bitcoin:" + MAINNET_GOOD_ADDRESS + "?amount=12.34&label=Hello&message=AMessage", CoinURI.convertToBitcoinURI(goodAddress, coinDefinition, parseCoin("12.34"), "Hello", "AMessage"));
        
        // example with spaces, ampersand and plus
        assertEquals("bitcoin:" + MAINNET_GOOD_ADDRESS + "?amount=12.34&label=Hello%20World&message=Mess%20%26%20age%20%2B%20hope", CoinURI.convertToBitcoinURI(goodAddress, coinDefinition, parseCoin("12.34"), "Hello World", "Mess & age + hope"));

        // no amount, label present, message present
        assertEquals("bitcoin:" + MAINNET_GOOD_ADDRESS + "?label=Hello&message=glory", CoinURI.convertToBitcoinURI(goodAddress, coinDefinition, null, "Hello", "glory"));
        
        // amount present, no label, message present
        assertEquals("bitcoin:" + MAINNET_GOOD_ADDRESS + "?amount=0.1&message=glory", CoinURI.convertToBitcoinURI(goodAddress, coinDefinition, parseCoin("0.1"), null, "glory"));
        assertEquals("bitcoin:" + MAINNET_GOOD_ADDRESS + "?amount=0.1&message=glory", CoinURI.convertToBitcoinURI(goodAddress, coinDefinition, parseCoin("0.1"), "", "glory"));

        // amount present, label present, no message
        assertEquals("bitcoin:" + MAINNET_GOOD_ADDRESS + "?amount=12.34&label=Hello", CoinURI.convertToBitcoinURI(goodAddress, coinDefinition, parseCoin("12.34"), "Hello", null));
        assertEquals("bitcoin:" + MAINNET_GOOD_ADDRESS + "?amount=12.34&label=Hello", CoinURI.convertToBitcoinURI(goodAddress, coinDefinition, parseCoin("12.34"), "Hello", ""));
              
        // amount present, no label, no message
        assertEquals("bitcoin:" + MAINNET_GOOD_ADDRESS + "?amount=1000", CoinURI.convertToBitcoinURI(goodAddress, coinDefinition, parseCoin("1000"), null, null));
        assertEquals("bitcoin:" + MAINNET_GOOD_ADDRESS + "?amount=1000", CoinURI.convertToBitcoinURI(goodAddress, coinDefinition, parseCoin("1000"), "", ""));
        
        // no amount, label present, no message
        assertEquals("bitcoin:" + MAINNET_GOOD_ADDRESS + "?label=Hello", CoinURI.convertToBitcoinURI(goodAddress, coinDefinition, null, "Hello", null));
        
        // no amount, no label, message present
        assertEquals("bitcoin:" + MAINNET_GOOD_ADDRESS + "?message=Agatha", CoinURI.convertToBitcoinURI(goodAddress, coinDefinition, null, null, "Agatha"));
        assertEquals("bitcoin:" + MAINNET_GOOD_ADDRESS + "?message=Agatha", CoinURI.convertToBitcoinURI(goodAddress, coinDefinition, null, "", "Agatha"));
      
        // no amount, no label, no message
        assertEquals("bitcoin:" + MAINNET_GOOD_ADDRESS, CoinURI.convertToBitcoinURI(goodAddress, coinDefinition, null, null, null));
        assertEquals("bitcoin:" + MAINNET_GOOD_ADDRESS, CoinURI.convertToBitcoinURI(goodAddress, coinDefinition, null, "", ""));
    }

    @Test
    public void testGood_Simple() throws CoinURIParseException {
        testObject = new CoinURI(MainNetParams.get(), BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS);
        assertNotNull(testObject);
        assertNull("Unexpected amount", testObject.getAmount());
        assertNull("Unexpected label", testObject.getLabel());
        assertEquals("Unexpected label", 20, testObject.getAddress().getHash160().length);
    }

    /**
     * Test a broken URI (bad scheme)
     */
    @Test
    public void testBad_Scheme() {
        try {
            testObject = new CoinURI(MainNetParams.get(), "blimpcoin:" + MAINNET_GOOD_ADDRESS);
            fail("Expecting BitcoinURIParseException");
        } catch (CoinURIParseException e) {
        }
    }

    /**
     * Test a broken URI (bad syntax)
     */
    @Test
    public void testBad_BadSyntax() {
        // Various illegal characters
        try {
            testObject = new CoinURI(MainNetParams.get(), BITCOIN_SCHEME + "|" + MAINNET_GOOD_ADDRESS);
            fail("Expecting BitcoinURIParseException");
        } catch (CoinURIParseException e) {
            assertTrue(e.getMessage().contains("Bad URI syntax"));
        }

        try {
            testObject = new CoinURI(MainNetParams.get(), BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS + "\\");
            fail("Expecting BitcoinURIParseException");
        } catch (CoinURIParseException e) {
            assertTrue(e.getMessage().contains("Bad URI syntax"));
        }

        // Separator without field
        try {
            testObject = new CoinURI(MainNetParams.get(), BITCOIN_SCHEME + ":");
            fail("Expecting BitcoinURIParseException");
        } catch (CoinURIParseException e) {
            assertTrue(e.getMessage().contains("Bad URI syntax"));
        }
    }

    /**
     * Test a broken URI (missing address)
     */
    @Test
    public void testBad_Address() {
        try {
            testObject = new CoinURI(MainNetParams.get(), BITCOIN_SCHEME);
            fail("Expecting BitcoinURIParseException");
        } catch (CoinURIParseException e) {
        }
    }

    /**
     * Test a broken URI (bad address type)
     */
    @Test
    public void testBad_IncorrectAddressType() {
        try {
            testObject = new CoinURI(TestNet3Params.get(), BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS);
            fail("Expecting BitcoinURIParseException");
        } catch (CoinURIParseException e) {
            assertTrue(e.getMessage().contains("Bad address"));
        }
    }

    /**
     * Handles a simple amount
     * 
     * @throws CoinURIParseException
     *             If something goes wrong
     */
    @Test
    public void testGood_Amount() throws CoinURIParseException {
        // Test the decimal parsing
        testObject = new CoinURI(MainNetParams.get(), BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                + "?amount=6543210.12345678");
        assertEquals("654321012345678", testObject.getAmount().toString());

        // Test the decimal parsing
        testObject = new CoinURI(MainNetParams.get(), BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                + "?amount=.12345678");
        assertEquals("12345678", testObject.getAmount().toString());

        // Test the integer parsing
        testObject = new CoinURI(MainNetParams.get(), BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                + "?amount=6543210");
        assertEquals("654321000000000", testObject.getAmount().toString());
    }

    /**
     * Handles a simple label
     * 
     * @throws CoinURIParseException
     *             If something goes wrong
     */
    @Test
    public void testGood_Label() throws CoinURIParseException {
        testObject = new CoinURI(MainNetParams.get(), BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                + "?label=Hello%20World");
        assertEquals("Hello World", testObject.getLabel());
    }

    /**
     * Handles a simple label with an embedded ampersand and plus
     * 
     * @throws CoinURIParseException
     *             If something goes wrong
     * @throws UnsupportedEncodingException 
     */
    @Test
    public void testGood_LabelWithAmpersandAndPlus() throws Exception {
        String testString = "Hello Earth & Mars + Venus";
        String encodedLabel = CoinURI.encodeURLString(testString);
        testObject = new CoinURI(MainNetParams.get(), BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS + "?label="
                + encodedLabel);
        assertEquals(testString, testObject.getLabel());
    }

    /**
     * Handles a Russian label (Unicode test)
     * 
     * @throws CoinURIParseException
     *             If something goes wrong
     * @throws UnsupportedEncodingException 
     */
    @Test
    public void testGood_LabelWithRussian() throws Exception {
        // Moscow in Russian in Cyrillic
        String moscowString = "\u041c\u043e\u0441\u043a\u0432\u0430";
        String encodedLabel = CoinURI.encodeURLString(moscowString);
        testObject = new CoinURI(MainNetParams.get(), BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS + "?label="
                + encodedLabel);
        assertEquals(moscowString, testObject.getLabel());
    }

    /**
     * Handles a simple message
     * 
     * @throws CoinURIParseException
     *             If something goes wrong
     */
    @Test
    public void testGood_Message() throws CoinURIParseException {
        testObject = new CoinURI(MainNetParams.get(), BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                + "?message=Hello%20World");
        assertEquals("Hello World", testObject.getMessage());
    }

    /**
     * Handles various well-formed combinations
     * 
     * @throws CoinURIParseException
     *             If something goes wrong
     */
    @Test
    public void testGood_Combinations() throws CoinURIParseException {
        testObject = new CoinURI(MainNetParams.get(), BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                + "?amount=6543210&label=Hello%20World&message=Be%20well");
        assertEquals(
                "BitcoinURI['amount'='654321000000000','label'='Hello World','message'='Be well','address'='1KzTSfqjF2iKCduwz59nv2uqh1W2JsTxZH']",
                testObject.toString());
    }

    /**
     * Handles a badly formatted amount field
     * 
     * @throws CoinURIParseException
     *             If something goes wrong
     */
    @Test
    public void testBad_Amount() throws CoinURIParseException {
        // Missing
        try {
            testObject = new CoinURI(MainNetParams.get(), BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                    + "?amount=");
            fail("Expecting BitcoinURIParseException");
        } catch (CoinURIParseException e) {
            assertTrue(e.getMessage().contains("amount"));
        }

        // Non-decimal (BIP 21)
        try {
            testObject = new CoinURI(MainNetParams.get(), BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                    + "?amount=12X4");
            fail("Expecting BitcoinURIParseException");
        } catch (CoinURIParseException e) {
            assertTrue(e.getMessage().contains("amount"));
        }
    }

    @Test
    public void testEmpty_Label() throws CoinURIParseException {
        assertNull(new CoinURI(MainNetParams.get(), BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                + "?label=").getLabel());
    }

    @Test
    public void testEmpty_Message() throws CoinURIParseException {
        assertNull(new CoinURI(MainNetParams.get(), BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                + "?message=").getMessage());
    }

    /**
     * Handles duplicated fields (sneaky address overwrite attack)
     * 
     * @throws CoinURIParseException
     *             If something goes wrong
     */
    @Test
    public void testBad_Duplicated() throws CoinURIParseException {
        try {
            testObject = new CoinURI(MainNetParams.get(), BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                    + "?address=aardvark");
            fail("Expecting BitcoinURIParseException");
        } catch (CoinURIParseException e) {
            assertTrue(e.getMessage().contains("address"));
        }
    }

    @Test
    public void testGood_ManyEquals() throws CoinURIParseException {
        assertEquals("aardvark=zebra", new CoinURI(MainNetParams.get(), BITCOIN_SCHEME + ":"
                + MAINNET_GOOD_ADDRESS + "?label=aardvark=zebra").getLabel());
    }
    
    /**
     * Handles unknown fields (required and not required)
     * 
     * @throws CoinURIParseException
     *             If something goes wrong
     */
    @Test
    public void testUnknown() throws CoinURIParseException {
        // Unknown not required field
        testObject = new CoinURI(MainNetParams.get(), BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                + "?aardvark=true");
        assertEquals("BitcoinURI['aardvark'='true','address'='1KzTSfqjF2iKCduwz59nv2uqh1W2JsTxZH']", testObject.toString());

        assertEquals("true", (String) testObject.getParameterByName("aardvark"));

        // Unknown not required field (isolated)
        try {
            testObject = new CoinURI(MainNetParams.get(), BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                    + "?aardvark");
            fail("Expecting BitcoinURIParseException");
        } catch (CoinURIParseException e) {
            assertTrue(e.getMessage().contains("no separator"));
        }

        // Unknown and required field
        try {
            testObject = new CoinURI(MainNetParams.get(), BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                    + "?req-aardvark=true");
            fail("Expecting BitcoinURIParseException");
        } catch (CoinURIParseException e) {
            assertTrue(e.getMessage().contains("req-aardvark"));
        }
    }

    @Test
    public void brokenURIs() throws CoinURIParseException {
        // Check we can parse the incorrectly formatted URIs produced by blockchain.info and its iPhone app.
        String str = "bitcoin://1KzTSfqjF2iKCduwz59nv2uqh1W2JsTxZH?amount=0.01000000";
        CoinURI uri = new CoinURI(str);
        assertEquals("1KzTSfqjF2iKCduwz59nv2uqh1W2JsTxZH", uri.getAddress().toString());
        assertEquals(cent(), uri.getAmount());
    }

    @Test(expected = CoinURIParseException.class)
    public void testBad_AmountTooPrecise() throws CoinURIParseException {
        new CoinURI(MainNetParams.get(), BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                + "?amount=0.123456789");
    }

    @Test(expected = CoinURIParseException.class)
    public void testBad_NegativeAmount() throws CoinURIParseException {
        new CoinURI(MainNetParams.get(), BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                + "?amount=-1");
    }

    @Test(expected = CoinURIParseException.class)
    public void testBad_TooLargeAmount() throws CoinURIParseException {
        new CoinURI(MainNetParams.get(), BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                + "?amount=100000000");
    }

    @Test
    public void testPaymentProtocolReq() throws Exception {
        // Non-backwards compatible form ...
        CoinURI uri = new CoinURI(TestNet3Params.get(), "bitcoin:?r=https%3A%2F%2Fbitcoincore.org%2F%7Egavin%2Ff.php%3Fh%3Db0f02e7cea67f168e25ec9b9f9d584f9");
        assertEquals("https://bitcoincore.org/~gavin/f.php?h=b0f02e7cea67f168e25ec9b9f9d584f9", uri.getPaymentRequestUrl());
        assertEquals(ImmutableList.of("https://bitcoincore.org/~gavin/f.php?h=b0f02e7cea67f168e25ec9b9f9d584f9"),
                uri.getPaymentRequestUrls());
        assertNull(uri.getAddress());
    }

    @Test
    public void testMultiplePaymentProtocolReq() throws Exception {
        CoinURI uri = new CoinURI(MainNetParams.get(),
                "bitcoin:?r=https%3A%2F%2Fbitcoincore.org%2F%7Egavin&r1=bt:112233445566");
        assertEquals(ImmutableList.of("bt:112233445566", "https://bitcoincore.org/~gavin"), uri.getPaymentRequestUrls());
        assertEquals("https://bitcoincore.org/~gavin", uri.getPaymentRequestUrl());
    }

    @Test
    public void testNoPaymentProtocolReq() throws Exception {
        CoinURI uri = new CoinURI(MainNetParams.get(), "bitcoin:" + MAINNET_GOOD_ADDRESS);
        assertNull(uri.getPaymentRequestUrl());
        assertEquals(ImmutableList.of(), uri.getPaymentRequestUrls());
        assertNotNull(uri.getAddress());
    }

    @Test
    public void testUnescapedPaymentProtocolReq() throws Exception {
        CoinURI uri = new CoinURI(TestNet3Params.get(),
                "bitcoin:?r=https://merchant.com/pay.php?h%3D2a8628fc2fbe");
        assertEquals("https://merchant.com/pay.php?h=2a8628fc2fbe", uri.getPaymentRequestUrl());
        assertEquals(ImmutableList.of("https://merchant.com/pay.php?h=2a8628fc2fbe"), uri.getPaymentRequestUrls());
        assertNull(uri.getAddress());
    }
}
