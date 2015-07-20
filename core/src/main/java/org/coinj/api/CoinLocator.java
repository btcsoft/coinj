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

package org.coinj.api;

import com.google.common.collect.ImmutableCollection;
import com.google.common.collect.ImmutableMap;

import javax.annotation.Nullable;
import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.ThreadSafe;
import java.util.Iterator;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Date: 4/16/15
 * Time: 6:30 PM
 *
 * @author Mikhail Kulikov
 */
@ThreadSafe
public final class CoinLocator {

    private static final ServiceLoader<CoinDefinition> loader = ServiceLoader.load(CoinDefinition.class);
    @GuardedBy("CoinLocator.class")
    private static final AtomicReference<ImmutableMap<String, CoinDefinition>> registry =
            new AtomicReference<ImmutableMap<String, CoinDefinition>>(ImmutableMap.<String, CoinDefinition>of());

    public static CoinDefinition discoverCoinDefinition() {
        final ImmutableMap<String, CoinDefinition> coinDefinitions = registry.get();
        if (coinDefinitions.isEmpty()) {
            final Iterator<CoinDefinition> implIterator = loader.iterator();

            if (!implIterator.hasNext())
                throw new CoinDiscoveryException("No registered coins found. Not with in-memory map, not with ServiceLoader mechanism.");

            final CoinDefinition def = implIterator.next();
            registerCoin(def);

            while (implIterator.hasNext()) {
                registerCoin(implIterator.next());
            }

            return def;
        } else {
            return coinDefinitions.values().iterator().next();
        }
    }

    @Nullable
    public static CoinDefinition getCoinDefinition(String coinName) {
        return getRegistryAndMaybeDiscover().get(coinName);
    }

    public static ImmutableCollection<CoinDefinition> getRegisteredCoins() {
        return getRegistryAndMaybeDiscover().values();
    }

    public static synchronized void registerCoin(CoinDefinition coinDefinition) {
        final ImmutableMap<String, CoinDefinition> definitions = registry.get();
        final String coinName = coinDefinition.getName();
        if (definitions.containsKey(coinName))
            return;
        registry.set(ImmutableMap.<String, CoinDefinition>builder().putAll(definitions).put(coinName, coinDefinition).build());
    }

    public static synchronized void unregisterCoin(CoinDefinition coinDefinition) {
        final ImmutableMap<String, CoinDefinition> definitions = registry.get();
        final String coinName = coinDefinition.getName();
        if (definitions.containsKey(coinName)) {
            final ImmutableMap.Builder<String, CoinDefinition> builder = ImmutableMap.builder();
            for (final Map.Entry<String, CoinDefinition> entry : definitions.entrySet()) {
                if (!entry.getKey().equals(coinName)) {
                    builder.put(entry);
                }
            }
            registry.set(builder.build());
        }
    }

    private static ImmutableMap<String, CoinDefinition> getRegistryAndMaybeDiscover() {
        ImmutableMap<String, CoinDefinition> map = registry.get();
        if (map.isEmpty()) {
            discoverCoinDefinition();
            map = registry.get();
        }
        return map;
    }

    private CoinLocator() {}

}
