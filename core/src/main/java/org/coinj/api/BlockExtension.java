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

import org.bitcoinj.core.Transaction;

import java.io.Serializable;

/**
 * Date: 5/14/15
 * Time: 5:17 PM
 *
 * @author Mikhail Kulikov
 */
public interface BlockExtension extends Serializable {

    public BlockExtension copy();

    /**
     * @throws org.bitcoinj.core.VerificationException
     */
    public void check();

    public void onTransactionAddition(Transaction tx);

}
