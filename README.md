### Welcome to coinj

The coinj library is universal Java tool for various crypto-coins, designed for easy implementation of crypto-coin (Bitcoin forks) protocols, which allows it to maintain a (coin specific) wallet and send/receive transactions without needing a local copy of coin's Core. It comes with full documentation and some example apps showing how to use it.

There are some minimal public API extensions mainly visible by ```CoinDefinition``` interface which you can pass to ```NetworkParameters``` through public constructor or through factory methods. If no ```CoinDefinition``` object was passed (if only conventional constructors and factory methods were used) then it will be discovered under the curtains through ```CoinLocator``` mechanism (which you can use to manually register coin definitions or just rely on behind-the-curtains code that is using Services Java API).

### Technologies

* Java 6 for the core modules, Java 7 for everything else
* [Maven 3+](http://maven.apache.org) - for building the project
* [Orchid](https://github.com/subgraph/Orchid) - for secure communications over [TOR](https://www.torproject.org)
* [Google Protocol Buffers](https://code.google.com/p/protobuf/) - for use with serialization and hardware communications
* [BitcoinJ](https://github.com/bitcoinj/bitcoinj) - upstream library, inner API of which was made alt-coins friendly and less static constants oriented

### Getting started

To get started, it is best to have the latest JDK and Maven installed. As of yet the HEAD of the `master` branch contains only the latest BitcoinJ development code, but various Coinj production releases are provided on feature branches. In the future it is planned to keep pace with BitcoinJ development in `master` branch.

#### Building from the command line

To perform a full build for the first time 
```
mvn clean package -DskipTests=true
```
To enable tests you'll need to build [coinj-bitcoin](https://github.com/btcsoft/coinj-bitcoin) project. Or wait when it will be available through maven-central (coming soon).

You can also run
```
mvn site:site
```
to generate a website with useful information like JavaDocs.

The outputs are under the `target` directory.

#### Building from an IDE

Alternatively, just import the project using your IDE. [IntelliJ](http://www.jetbrains.com/idea/download/) has Maven integration built-in and has a free Community Edition. Simply use `File | Import Project` and locate the `pom.xml` in the root of the cloned project source tree.

### Example applications

These are found in the `examples` module.

### Where next?

Actual implementations for various crypto-coin networks can be found here:

* [coinj-bitcoin](https://github.com/btcsoft/coinj-bitcoin) - bitcoin network, proof of concept of sort
* [coinj-litecoin](https://github.com/btcsoft/coinj-litecoin) - litecoin network library, you may call it standardized analogue to BitcoinJ for Litecoin; there are some coin-specific tests migrated from BitcoinJ with test data specifically altered for LTC's
* [coinj-dash](https://github.com/btcsoft/dash-litecoin) - [DASH](https://dashpay.io) network library; currently under active development but not yet ready for production