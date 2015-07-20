/*
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

package org.bitcoinj.utils;

import org.coinj.api.CoinDefinition;
import org.coinj.api.CoinLocator;

import javax.annotation.concurrent.ThreadSafe;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Date: 4/17/15
 * Time: 6:06 PM
 *
 * @author Mikhail Kulikov
 */
@ThreadSafe
public class DefinitionsRegistry<Params> {

    private final ConcurrentHashMap<CoinDefinition, Params> paramsRegistry = new ConcurrentHashMap<CoinDefinition, Params>(10, 1.0f, 2);
    private final DefinitionValuesFactory<Params> paramsFactory;

    public DefinitionsRegistry(DefinitionValuesFactory<Params> paramsFactory) {
        this.paramsFactory = paramsFactory;
    }

    public Params get(CoinDefinition def, Object... extension) {
        Params instance = paramsRegistry.get(def);
        if (instance == null) {
            instance = paramsFactory instanceof DefinitionValuesExtendedFactory && extension.length > 0
                    ? ((DefinitionValuesExtendedFactory<Params>) paramsFactory).createParams(def, extension)
                    : paramsFactory.createParams(def);
            Params old = paramsRegistry.putIfAbsent(def, instance);
            if (old != null) {
                instance = old;
            }
        }
        return instance;
    }

    public Params get(Object... objects) {
        return get(CoinLocator.discoverCoinDefinition(), objects);
    }

}
