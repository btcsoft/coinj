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
import org.bitcoinj.core.TransactionConfidence;

import javax.annotation.Nullable;
import java.io.Serializable;

/**
 * Date: 5/14/15
 * Time: 9:56 PM
 *
 * @author Mikhail Kulikov
 */
public interface TransactionConfidenceExtension extends Serializable {

    /**
     * Check if this implementation supports confidenceType.
     */
    public boolean acknowledgeExtendedConfidenceType(TransactionConfidence.ConfidenceType confidenceType);

    public void appendToStringBuilder(StringBuilder builder, TransactionConfidence confidence);

    /**
     * False if not allowed.
     */
    public boolean isAllowedAppearanceAtChainHeight(TransactionConfidence.ConfidenceType confidenceType);

    /**
     * Called from TransactionConfidence.setAppearedAtChainHeight(int).
     */
    public boolean allowBuildingTypeIfChainAppearanceSet(TransactionConfidence.ConfidenceType confidenceType);

    /**
     * Called from TransactionConfidence.setConfidenceType(ConfidenceType).
     */
    public boolean mustDoDepthNullSettingAtSetTypeIfNotPending(TransactionConfidence.ConfidenceType confidenceType);

    /**
     * Called from TransactionConfidence.isTransactionMature(int).
     * @return true if transaction with such ConfidenceType is to be trusted.
     */
    public boolean isMatureConfidenceType(TransactionConfidence.ConfidenceType confidenceType);

    /**
     * Called from TransactionConfidence.isTransactionMature(int).
     * @return true if additional conditions are in order.
     */
    public boolean haveSpecialMaturityConditions(TransactionConfidence.ConfidenceType confidenceType);

    /**
     * Called from TransactionConfidence.isTransactionMature(int).
     */
    public boolean specialMaturityConditions(TransactionConfidence.ConfidenceType confidenceType);

    /**
     * Called from DefaultCoinSelector.isSelectable(Transaction).
     * @return true if transaction have coins selectable by DefaultCoinSelector's strategy.
     */
    public boolean isCoinsSelectableByDefault(Transaction tx);

    @Nullable
    public String getConfidenceTypeName(TransactionConfidence.ConfidenceType confidenceType);

    public boolean isExtendedConfidenceRelevant(Transaction tx);

    public TransactionConfidence.ConfidenceType markBroadcastByExtendedConfidenceType();

    public TransactionConfidenceExtension copy();

}
