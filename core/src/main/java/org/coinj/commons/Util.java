/**
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

package org.coinj.commons;

import org.coinj.api.CoinDefinition;
import org.coinj.api.NonStandardNetworkException;

import javax.annotation.Nullable;

/**
 * Date: 4/30/15
 * Time: 5:21 PM
 *
 * @author Mikhail Kulikov
 */
public final class Util {

    public static final Object UNSUPPORTED_SIG = new Object();

    public static Object networkCheck(@Nullable Object first, @Nullable Object second, @Nullable Object third, CoinDefinition.StandardNetworkId networkId, String coinName) {
        if (CoinDefinition.MAIN_NETWORK_STANDARD.equals(networkId)) {
            checkUnsupportedStandard(first, networkId, coinName);
            return first;
        } else if (CoinDefinition.TEST_NETWORK_STANDARD.equals(networkId)) {
            checkUnsupportedStandard(second, networkId, coinName);
            return second;
        } else if (CoinDefinition.REG_TEST_STANDARD.equals(networkId)) {
            checkUnsupportedStandard(third, networkId, coinName);
            return third;
        } else {
            throw new NonStandardNetworkException(networkId.str(), coinName);
        }
    }

    public static Object impossibleNullCheck(@Nullable Object obj) {
        if (obj == null)
            throw new RuntimeException("Impossible null result");
        return obj;
    }

    private static void checkUnsupportedStandard(Object obj, CoinDefinition.StandardNetworkId networkId, String coinName) {
        if (UNSUPPORTED_SIG == obj) {
            throw new NonStandardNetworkException(networkId.str(), coinName);
        }
    }

    private Util() {}

}
