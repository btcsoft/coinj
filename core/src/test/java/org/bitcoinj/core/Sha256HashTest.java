package org.bitcoinj.core;

import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.*;

/**
 * Date: 6/19/15
 * Time: 12:26 PM
 *
 * @author Mikhail Kulikov
 */
public class Sha256HashTest {

    @Test
    public void testCreate() throws Exception {
        Sha256Hash hash = new Sha256Hash("95640e0641aed2b246f1dd372b2bf10666ccb4ccbaea6abe3e039db4122d50d1");
        BigInteger hashAsInt = hash.toBigInteger();
        Sha256Hash hashFromInt = new Sha256Hash(hashAsInt);
        assertEquals("BigInteger constructor failed", hash, hashFromInt);
        hash = new Sha256Hash("00000000000000001567c1d4e1f97bab6960ef15bfc48df0fed6e4b3468ebfaf");
        hashAsInt = hash.toBigInteger();
        hashFromInt = new Sha256Hash(hashAsInt);
        assertEquals("BigInteger constructor failed", hash, hashFromInt);
    }

}
