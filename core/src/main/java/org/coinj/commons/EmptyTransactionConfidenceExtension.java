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

import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionConfidence;
import org.coinj.api.TransactionConfidenceExtension;

import javax.annotation.Nullable;

/**
 * Date: 5/15/15
 * Time: 10:14 PM
 *
 * @author Mikhail Kulikov
 */
public class EmptyTransactionConfidenceExtension implements TransactionConfidenceExtension {

    public static final EmptyTransactionConfidenceExtension INSTANCE = new EmptyTransactionConfidenceExtension();

    protected EmptyTransactionConfidenceExtension() {}

    private static final long serialVersionUID = 1L;

    @Override
    public boolean acknowledgeExtendedConfidenceType(TransactionConfidence.ConfidenceType confidenceType) {
        return false;
    }

    @Override
    public void appendToStringBuilder(StringBuilder builder, TransactionConfidence confidence) {
        throw new UnsupportedOperationException("This TransactionConfidenceExtension is for coins without TransactionConfidence extensions hence this code must be unreachable.");
    }

    @Override
    public boolean isAllowedAppearanceAtChainHeight(TransactionConfidence.ConfidenceType confidenceType) {
        return false;
    }

    @Override
    public boolean allowBuildingTypeIfChainAppearanceSet(TransactionConfidence.ConfidenceType confidenceType) {
        return true; // !important! or else will break default Wallet
    }

    @Override
    public boolean mustDoDepthNullSettingAtSetTypeIfNotPending(TransactionConfidence.ConfidenceType confidenceType) {
        return false;
    }

    @Override
    public boolean isMatureConfidenceType(TransactionConfidence.ConfidenceType confidenceType) {
        return false;
    }

    @Override
    public boolean haveSpecialMaturityConditions(TransactionConfidence.ConfidenceType confidenceType) {
        return false;
    }

    @Override
    public boolean specialMaturityConditions(TransactionConfidence.ConfidenceType confidenceType) {
        return false;
    }

    @Override
    public boolean isCoinsSelectableByDefault(Transaction tx) {
        return false;
    }

    @Nullable
    @Override
    public String getConfidenceTypeName(TransactionConfidence.ConfidenceType confidenceType) {
        return null;
    }

    @Override
    public TransactionConfidenceExtension copy() {
        return INSTANCE;
    }

    @Override
    public boolean isExtendedConfidenceRelevant(Transaction tx) {
        return false;
    }

    @Override
    public TransactionConfidence.ConfidenceType markBroadcastByExtendedConfidenceType() {
        return TransactionConfidence.ConfidenceType.PENDING;
    }

}
