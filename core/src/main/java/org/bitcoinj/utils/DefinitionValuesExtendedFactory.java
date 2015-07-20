package org.bitcoinj.utils;

import org.coinj.api.CoinDefinition;

/**
 * Date: 6/19/15
 * Time: 7:01 PM
 *
 * @author Mikhail Kulikov
 */
public interface DefinitionValuesExtendedFactory<Params> extends DefinitionValuesFactory<Params> {

    public Params createParams(CoinDefinition coinDefinition, Object... optional);

}
