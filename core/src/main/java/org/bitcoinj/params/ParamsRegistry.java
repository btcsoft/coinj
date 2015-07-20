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

package org.bitcoinj.params;

import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.utils.DefinitionsRegistry;

import javax.annotation.concurrent.ThreadSafe;

/**
 * Date: 4/16/15
 * Time: 7:31 PM
 *
 * @author Mikhail Kulikov
 */
@ThreadSafe
public final class ParamsRegistry<Params extends NetworkParameters> extends DefinitionsRegistry<Params> {

    ParamsRegistry(ParamsFactory<Params> paramsFactory) {
        super(paramsFactory);
    }

}
