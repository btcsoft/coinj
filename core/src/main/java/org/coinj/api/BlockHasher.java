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

import org.bitcoinj.core.Block;
import org.bitcoinj.core.Sha256Hash;

import javax.annotation.Nonnull;

/**
 * Date: 4/14/15
 * Time: 6:44 PM
 *
 * @author Mikhail Kulikov
 */
public interface BlockHasher {

    /**
     * Implementations must conform to non-null cached semantics (e.g. if (hashCache == null) initHash(block); return hashCache;).
     * So if unCache() is called cache will be set to null.
     * @return block hash as we see it on block explorers.
     */
    @Nonnull
    public Sha256Hash getHash(Block block);

    /**
     * Implementations must conform to non-null cached semantics (e.g. if (powHashCache == null) initProofOfWorkHash(block); return powHashCache;).
     * So if unCache() is called cache will be set to null.
     * @return block hash to use in Proof Of Work check.
     */
    @Nonnull
    public Sha256Hash getProofOfWorkHash(Block block);

    /**
     * Init hash as we see it on block explorers.
     */
    public void initHash(Block block);

    /**
     * Init hash used in Proof of Work check.
     */
    public void initProofOfWorkHash(Block block);

    /**
     * Clear caches.
     */
    public void unCache();

    /**
     * Manual cloning method, 'cause Cloneable is broken in Java.
     * @return copy.
     */
    public BlockHasher copy();

}
