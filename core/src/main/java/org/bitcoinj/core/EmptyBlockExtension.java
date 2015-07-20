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

package org.bitcoinj.core;

import org.coinj.api.BlockExtension;

/**
 * Date: 5/15/15
 * Time: 8:09 PM
 *
 * @author Mikhail Kulikov
 */
public class EmptyBlockExtension implements BlockExtension {

    public static final EmptyBlockExtension INSTANCE = new EmptyBlockExtension();

    private static final long serialVersionUID = 1L;

    protected EmptyBlockExtension() {}

    @Override
    public EmptyBlockExtension copy() {
        return INSTANCE;
    }

    @Override
    public void check() {}

    @Override
    public void onTransactionAddition(Transaction tx) {}

}
