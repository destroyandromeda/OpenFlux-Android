package io.openflux.app;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class OpenFluxVpnServiceTest {
    private static final byte[] A_QUERY = hex(
            "1234010000010000000000000178076578616d706c650000010001");
    private static final byte[] AAAA_QUERY = hex(
            "1234010000010000000000000178076578616d706c6500001c0001");

    @Test
    public void preservesNonAaaaResponseByteForByte() {
        byte[] cnameAndA = hex(
                "1234818000010002000000000178076578616d706c650000010001" +
                "c00c000500010000003c0004017900c0" +
                "c02b000100010000003c00047f000001");

        assertArrayEquals(cnameAndA,
                OpenFluxVpnService.filterAaaaResponse(A_QUERY, cnameAndA));
    }

    @Test
    public void returnsValidNodataForAaaaResponseWithEdns() {
        byte[] aaaaAndEdns = hex(
                "1234838000010001000000010178076578616d706c6500001c0001" +
                "c00c001c00010000003c001000000000000000000000000000000001" +
                "0000291000000000000000");

        byte[] result = OpenFluxVpnService.filterAaaaResponse(AAAA_QUERY, aaaaAndEdns);

        assertArrayEquals(hex("1234818000010000000000000178076578616d706c6500001c0001"), result);
        assertEquals(0, result[2] & 0x02);
    }

    private static byte[] hex(String value) {
        byte[] result = new byte[value.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        }
        return result;
    }
}
