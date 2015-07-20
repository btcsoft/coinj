/**
 * Copyright 2014 Andreas Schildbach
 * Copyright 2015 BitTechCenter Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.core;

import com.google.common.math.LongMath;
import org.bitcoinj.utils.DefinitionValuesFactory;
import org.bitcoinj.utils.DefinitionsRegistry;
import org.bitcoinj.utils.MonetaryFormat;
import org.coinj.api.CoinDefinition;
import org.coinj.api.CoinLocator;

import javax.annotation.Nonnull;
import java.io.Serializable;
import java.math.BigDecimal;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

/**
 * Represents a monetary Bitcoin value. This class is immutable.
 */
public final class Coin implements Monetary, Comparable<Coin>, Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * Number of decimals for one crypto-coin. This constant is useful for quick adapting to other coins because a lot of
     * constants derive from it.
     */
    public static final int SMALLEST_UNIT_EXPONENT = 8;

    /**
     * The number of 'satoshis' equal to one coin.
     */
    public static final long COIN_VALUE = LongMath.pow(10, SMALLEST_UNIT_EXPONENT);

    static final class ZeroFactory implements DefinitionValuesFactory<Coin> {
        private ZeroFactory() {}

        @Override
        public Coin createParams(CoinDefinition coinDefinition) {
            return Coin.valueOf(0, coinDefinition);
        }
    }
    private static final DefinitionsRegistry<Coin> zeroRegistry = new DefinitionsRegistry<Coin>(new ZeroFactory());

    /**
     * Zero Bitcoins.
     */
    public static Coin zero() {
        return zeroRegistry.get();
    }
    /**
     * Zero Bitcoins.
     */
    public static Coin zero(CoinDefinition def) {
        return zeroRegistry.get(def);
    }
    /**
     * Zero Bitcoins.
     */
    public static Coin zero(NetworkParameters params) {
        return zeroRegistry.get(params.getCoinDefinition());
    }

    static final class CoinFactory implements DefinitionValuesFactory<Coin> {
        private CoinFactory() {}

        @Override
        public Coin createParams(CoinDefinition coinDefinition) {
            return valueOf(COIN_VALUE, coinDefinition);
        }
    }
    private static final DefinitionsRegistry<Coin> coinRegistry = new DefinitionsRegistry<Coin>(new CoinFactory());

    /**
     * One Bitcoin.
     */
    public static Coin coin() {
        return coinRegistry.get();
    }
    /**
     * One Bitcoin.
     */
    public static Coin coin(CoinDefinition def) {
        return coinRegistry.get(def);
    }
    /**
     * One Bitcoin.
     */
    public static Coin coin(NetworkParameters params) {
        return coinRegistry.get(params.getCoinDefinition());
    }

    static final class CentFactory implements DefinitionValuesFactory<Coin> {
        private CentFactory() {}

        @Override
        public Coin createParams(CoinDefinition coinDefinition) {
            return Coin.valueOf(COIN_VALUE, coinDefinition).divide(100);
        }
    }
    private static final DefinitionsRegistry<Coin> centRegistry = new DefinitionsRegistry<Coin>(new CentFactory());

    /**
     * 0.01 Bitcoins. This unit is not really used much.
     */
    public static Coin cent() {
        return centRegistry.get();
    }
    /**
     * 0.01 Bitcoins. This unit is not really used much.
     */
    public static Coin cent(CoinDefinition def) {
        return centRegistry.get(def);
    }
    /**
     * 0.01 Bitcoins. This unit is not really used much.
     */
    public static Coin cent(NetworkParameters params) {
        return centRegistry.get(params.getCoinDefinition());
    }

    static final class MilliCoinFactory implements DefinitionValuesFactory<Coin> {
        private MilliCoinFactory() {}

        @Override
        public Coin createParams(CoinDefinition coinDefinition) {
            return Coin.valueOf(COIN_VALUE, coinDefinition).divide(1000);
        }
    }
    private static final DefinitionsRegistry<Coin> milliCoinRegistry = new DefinitionsRegistry<Coin>(new MilliCoinFactory());

    /**
     * 0.001 Bitcoins, also known as 1 mBTC.
     */
    public static Coin milliCoin() {
        return milliCoinRegistry.get();
    }
    /**
     * 0.001 Bitcoins, also known as 1 mBTC.
     */
    public static Coin milliCoin(CoinDefinition def) {
        return milliCoinRegistry.get(def);
    }
    /**
     * 0.001 Bitcoins, also known as 1 mBTC.
     */
    public static Coin milliCoin(NetworkParameters params) {
        return milliCoinRegistry.get(params.getCoinDefinition());
    }

    static final class MicroCoinFactory implements DefinitionValuesFactory<Coin> {
        private MicroCoinFactory() {}

        @Override
        public Coin createParams(CoinDefinition coinDefinition) {
            return Coin.valueOf(COIN_VALUE, coinDefinition).divide(1000000);
        }
    }
    private static final DefinitionsRegistry<Coin> microCoinRegistry = new DefinitionsRegistry<Coin>(new MicroCoinFactory());

    /**
     * 0.000001 Bitcoins, also known as 1 µBTC or 1 uBTC.
     */
    public static Coin microCoin() {
        return microCoinRegistry.get();
    }
    /**
     * 0.000001 Bitcoins, also known as 1 µBTC or 1 uBTC.
     */
    public static Coin microCoin(CoinDefinition def) {
        return microCoinRegistry.get(def);
    }
    /**
     * 0.000001 Bitcoins, also known as 1 µBTC or 1 uBTC.
     */
    public static Coin microCoin(NetworkParameters params) {
        return microCoinRegistry.get(params.getCoinDefinition());
    }

    static final class SatoshiFactory implements DefinitionValuesFactory<Coin> {
        private SatoshiFactory() {}

        @Override
        public Coin createParams(CoinDefinition coinDefinition) {
            return Coin.valueOf(1, coinDefinition);
        }
    }
    private static final DefinitionsRegistry<Coin> satoshiRegistry = new DefinitionsRegistry<Coin>(new SatoshiFactory());

    /**
     * A satoshi is the smallest unit that can be transferred. 100 million of them fit into a Bitcoin.
     */
    public static Coin satoshi() {
        return satoshiRegistry.get();
    }
    /**
     * A satoshi is the smallest unit that can be transferred. 100 million of them fit into a Bitcoin.
     */
    public static Coin satoshi(CoinDefinition def) {
        return satoshiRegistry.get(def);
    }
    /**
     * A satoshi is the smallest unit that can be transferred. 100 million of them fit into a Bitcoin.
     */
    public static Coin satoshi(NetworkParameters params) {
        return satoshiRegistry.get(params.getCoinDefinition());
    }

    static final class FiftyCoinsFactory implements DefinitionValuesFactory<Coin> {
        private FiftyCoinsFactory() {}

        @Override
        public Coin createParams(CoinDefinition coinDefinition) {
            return Coin.valueOf(COIN_VALUE, coinDefinition).multiply(50);
        }
    }
    private static final DefinitionsRegistry<Coin> fiftyCoinsRegistry = new DefinitionsRegistry<Coin>(new FiftyCoinsFactory());

    public static Coin fiftyCoins() {
        return fiftyCoinsRegistry.get();
    }
    public static Coin fiftyCoins(CoinDefinition def) {
        return fiftyCoinsRegistry.get(def);
    }
    public static Coin fiftyCoins(NetworkParameters params) {
        return fiftyCoinsRegistry.get(params.getCoinDefinition());
    }

    static final class NegativeSatoshiFactory implements DefinitionValuesFactory<Coin> {
        private NegativeSatoshiFactory() {}

        @Override
        public Coin createParams(CoinDefinition coinDefinition) {
            return Coin.valueOf(-1, coinDefinition);
        }
    }
    private static final DefinitionsRegistry<Coin> negativeSatoshiRegistry = new DefinitionsRegistry<Coin>(new NegativeSatoshiFactory());

    /**
     * Represents a monetary value of minus one satoshi.
     */
    public static Coin negativeSatoshi() {
        return negativeSatoshiRegistry.get();
    }
    /**
     * Represents a monetary value of minus one satoshi.
     */
    public static Coin negativeSatoshi(CoinDefinition def) {
        return negativeSatoshiRegistry.get(def);
    }
    /**
     * Represents a monetary value of minus one satoshi.
     */
    public static Coin negativeSatoshi(NetworkParameters params) {
        return negativeSatoshiRegistry.get(params.getCoinDefinition());
    }


    /**
     * The number of satoshis of this monetary value.
     */
    public final long value;
    private final CoinDefinition definition;

    private Coin(final long satoshis, final CoinDefinition def) {
        checkNotNull(def);
        final long maxSatoshis = COIN_VALUE * def.getMaxCoins();
        checkArgument(-maxSatoshis <= satoshis && satoshis <= maxSatoshis,
            "%s satoshis exceeds maximum possible quantity of %s.", satoshis, def.getName());
        this.value = satoshis;
        definition = def;
    }

    public static Coin valueOf(final long satoshis) {
        return valueOf(satoshis, CoinLocator.discoverCoinDefinition());
    }

    public static Coin valueOf(final long satoshis, final CoinDefinition def) {
        return new Coin(satoshis, def);
    }

    public static Coin valueOf(final long satoshis, final NetworkParameters params) {
        return new Coin(satoshis, params.getCoinDefinition());
    }

    @Override
    public int smallestUnitExponent() {
        return SMALLEST_UNIT_EXPONENT;
    }

    /**
     * Returns the number of satoshis of this monetary value.
     */
    @Override
    public long getValue() {
        return value;
    }

    /**
     * Convert an amount expressed in the way humans are used to into satoshis.
     */
    public static Coin valueOf(final int coins, final int cents) {
        return valueOf(coins, cents, CoinLocator.discoverCoinDefinition());
    }

    /**
     * Convert an amount expressed in the way humans are used to into satoshis.
     */
    public static Coin valueOf(final int coins, final int cents, final NetworkParameters params) {
        return valueOf(coins, cents, params.getCoinDefinition());
    }

    /**
     * Convert an amount expressed in the way humans are used to into satoshis.
     */
    public static Coin valueOf(final int coins, final int cents, CoinDefinition coinDefinition) {
        checkArgument(cents < 100);
        checkArgument(cents >= 0);
        checkArgument(coins >= 0);
        final Coin c = coin(coinDefinition);
        return c.multiply(coins).add(c.divide(100).multiply(cents));
    }

    /**
     * Parses an amount expressed in the way humans are used to.<p>
     * <p/>
     * This takes string in a format understood by {@link BigDecimal#BigDecimal(String)},
     * for example "0", "1", "0.10", "1.23E3", "1234.5E-5".
     *
     * @throws IllegalArgumentException if you try to specify fractional satoshis, or a value out of range.
     */
    public static Coin parseCoin(final String str) {
        return Coin.valueOf(new BigDecimal(str).movePointRight(SMALLEST_UNIT_EXPONENT).toBigIntegerExact().longValue());
    }

    public Coin add(final Coin value) {
        checkCoinPair(this, value);
        return new Coin(LongMath.checkedAdd(this.value, value.value), definition);
    }

    public Coin subtract(final Coin value) {
        checkCoinPair(this, value);
        return new Coin(LongMath.checkedSubtract(this.value, value.value), definition);
    }

    public Coin multiply(final long factor) {
        return new Coin(LongMath.checkedMultiply(this.value, factor), definition);
    }

    public Coin divide(final long divisor) {
        return new Coin(this.value / divisor, definition);
    }

    public Coin[] divideAndRemainder(final long divisor) {
        return new Coin[] { new Coin(this.value / divisor, definition), new Coin(this.value % divisor, definition) };
    }

    public long divide(final Coin divisor) {
        checkCoinPair(this, divisor);
        return this.value / divisor.value;
    }

    /**
     * Returns true if and only if this instance represents a monetary value greater than zero,
     * otherwise false.
     */
    public boolean isPositive() {
        return signum() == 1;
    }

    /**
     * Returns true if and only if this instance represents a monetary value less than zero,
     * otherwise false.
     */
    public boolean isNegative() {
        return signum() == -1;
    }

    /**
     * Returns true if and only if this instance represents zero monetary value,
     * otherwise false.
     */
    public boolean isZero() {
        return signum() == 0;
    }

    /**
     * Returns true if the monetary value represented by this instance is greater than that
     * of the given other Coin, otherwise false.
     */
    public boolean isGreaterThan(Coin other) {
        checkCoinPair(this, other);
        return compareTo(other) > 0;
    }

    /**
     * Returns true if the monetary value represented by this instance is less than that
     * of the given other Coin, otherwise false.
     */
    public boolean isLessThan(Coin other) {
        checkCoinPair(this, other);
        return compareTo(other) < 0;
    }

    public Coin shiftLeft(final int n) {
        return new Coin(this.value << n, definition);
    }

    public Coin shiftRight(final int n) {
        return new Coin(this.value >> n, definition);
    }

    @Override
    public int signum() {
        if (this.value == 0)
            return 0;
        return this.value < 0 ? -1 : 1;
    }

    public Coin negate() {
        return new Coin(-this.value, definition);
    }

    /**
     * Returns the number of satoshis of this monetary value. It's deprecated in favour of accessing {@link #value}
     * directly.
     */
    public long longValue() {
        return this.value;
    }

    private static final MonetaryFormat FRIENDLY_FORMAT = MonetaryFormat.BTC.minDecimals(2).repeatOptionalDecimals(1, 6).postfixCode();

    /**
     * Returns the value as a 0.12 type string. More digits after the decimal place will be used
     * if necessary, but two will always be present.
     */
    public String toFriendlyString() {
        return FRIENDLY_FORMAT.code(definition.getTicker()).format(this).toString();
    }

    private static final MonetaryFormat PLAIN_FORMAT = MonetaryFormat.BTC.minDecimals(0).repeatOptionalDecimals(1, 8).noCode();

    public String  getCurrencyName() {
        return definition.getName();
    }

    static final class MaxMoneyFactory implements DefinitionValuesFactory<Coin> {
        private MaxMoneyFactory() {}

        @Override
        public Coin createParams(CoinDefinition coinDefinition) {
            return Coin.valueOf(COIN_VALUE, coinDefinition).multiply(coinDefinition.getMaxCoins());
        }
    }
    private static final DefinitionsRegistry<Coin> maxMoneyRegistry = new DefinitionsRegistry<Coin>(new MaxMoneyFactory());

    public static Coin maxMoney() {
        return maxMoneyRegistry.get();
    }
    public static Coin maxMoney(CoinDefinition coinDefinition) {
        return maxMoneyRegistry.get(coinDefinition);
    }

    public Coin getMaxMoney() {
        return maxMoney(definition);
    }

    public Coin getZero() {
        return zero(definition);
    }

    public Coin getCoin() {
        return coin(definition);
    }

    public Coin getCent() {
        return cent(definition);
    }

    public Coin getMilliCoin() {
        return milliCoin(definition);
    }

    public Coin getMicroCoin() {
        return microCoin(definition);
    }

    public Coin getSatoshi() {
        return satoshi(definition);
    }

    public Coin getNegativeSatoshi() {
        return negativeSatoshi(definition);
    }

    /**
     * <p>
     * Returns the value as a plain string denominated in BTC.
     * The result is unformatted with no trailing zeroes.
     * For instance, a value of 150000 satoshis gives an output string of "0.0015" BTC
     * </p>
     */
    public String toPlainString() {
        return PLAIN_FORMAT.format(this).toString();
    }

    @Override
    public String toString() {
        return Long.toString(value);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        final Coin coin = (Coin) o;

        return value == coin.value && definition.equals(coin.definition);
    }

    @Override
    public int hashCode() {
        int result = (int) (value ^ (value >>> 32));
        result = 31 * result + definition.hashCode();
        return result;
    }

    @Override
    public int compareTo(@Nonnull final Coin other) {
        checkCoinPair(this, other);
        if (this.value == other.value)
            return 0;
        return this.value > other.value ? 1 : -1;
    }

    private static void checkCoinPair(Coin c1, Coin c2) {
        if (!c1.definition.equals(c2.definition)) {
            throw new IllegalArgumentException("Coins from different crypto currencies -- " + c1.definition.getName() + ": " + c1 + "; " + c2.definition.getName() + ": " + c2);
        }
    }

}
