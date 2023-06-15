![Sawtooth=DGT](http://dgt.world/images/logo.svg)

# DGT-Matagami

DGT (Digital Transactions Platform) is a distributed blockchain platform focused on WEB 3 solutions, em-phasizing tokenization and privacy. Developed since 2018 as a fork of Hyperledger Sawtooth, DGT introduces significant changes, including a hybrid network design with distinct permissioned segments. 


**VERSIONS**:
-----------
DGT (Digital Transactions Platform) has undergone iterative development since its inception, with each ver-sion introducing enhancements and improvements. The following is a summary of the key versions of DGT:
-	KAWARTHA (2019): The initial version of DGT laid the foundation for the platform, establishing the core architecture and transaction processing capabilities.
-	MISSISSAUGA (2020): This version expanded on the capabilities of DGT, introducing advanced features such as smart contract support and additional transaction families.
-	MATAGAMI (2022, current version): Building upon previous versions, MATAGAMI brought significant improvements in scalability, network topology, and consensus mechanisms. It introduced the concept of hierarchical clustering and the use of Proof-of-Stake (PoS) consensus at the network level.
-	ATHABASCA (2023, upcoming version): The forthcoming ATHABASCA release aims to further enhance interoperability (Ethereum Bridge) and privacy-preserving features and introduce mechanisms for private intersections of datasets (SMPC PSI). It will also refine existing components and address any identified issues.
-	ETHOBICO (planned release, 2024): ETHOBICO will focus on interoperability and bridge-building capabilities, enabling seamless integration with other blockchain networks and facilitating cross-chain transactions.
-	HARRICANA (planned release, 2025): HARRICANA is envisioned as a milestone version, incorporating advanced functionalities, improved performance, and security enhancements. It will continue to push the boundaries of DGT's capabilities.

**ARCHITECTURE**:
-----------
The architecture comprises key components to ensure integrity, security, and efficiency:
1.	Network Topology:
-	The DGT network is organized into interconnected clusters forming a hierarchical and scalable struc-ture.
-	Permalinks mechanism is employed to maintain network consistency, ensuring reliable and consistent data exchange instead of using a gossip-based approach.
-	Cluster nodes operate independently within their respective segments, with designated leaders and arbitrators.
2.	Consensus Mechanisms:
-	DGT utilizes a two-level consensus mechanism to ensure transaction validity and agreement.
-	Byzantine Fault Tolerant (BFT) consensus algorithms, such as PBFT (Lazy Mode), Pipelined HotStuff (Fast Run Mode), and Alpane (Lagrange Construction), facilitate consensus within individual clusters.
-	At the network level, a ring of arbitrators utilizes Proof-of-Stake (PoS) consensus to make final deci-sions and resolve conflicts between clusters.
3.	Blockchain Layer:
-	DGT employs a blockchain as the underlying technology to record and validate transactions, ensuring transparency and security.
-	The blockchain incorporates the use of a DAG-based data storage structure, allowing for transaction linking and establishing internal network time.
4.	Transaction Families:
-	DGT supports various transaction families that address specific use cases and functionalities.
-	These families define the structure, rules, and actions associated with specific types of transactions, such as cryptocurrency transfers, asset issuance, voting, and privacy-preserving transactions.
-	DGT provides several default families, including dgt (basic commands), topology (network settings), xcert (certificate management), bgt (test transactions), and dec (native currency support).
5.	Off-chain Calculation:
-	The platform includes notaries, specialized nodes equipped with secure storage and organized in a ring structure.
-	Notaries provide off-chain calculation capabilities and maintain synchronization through the RAFT mechanism.
-	A separate notary family enables writing to the register and reading transactions, supporting func-tionalities such as decentralized identifications (DID) and KYC certifications.
6.	Tokenization:
-	DGT offers optional tokenization capabilities through the DEC super-family of transactions.
-	The DEC family facilitates the issuance, management, and transfer of internal DEC tokens.
-	Minting mechanisms distribute tokens among network nodes, while banking operations enable DEC transfers, invoicing, and virtual card issuance.
-	The platform supports secondary token issuance and configuration.
7.	APIs and SDKs:
-	DGT provides APIs and SDKs for developers to interact with the blockchain and build applications on top of the platform.
-	These tools offer simplified interfaces and programming libraries to access and utilize DGT's function-alities.
8.	Security Measures:
-	DGT incorporates robust security measures, including cryptographic algorithms, digital signatures, and encryption techniques.
-	OpenSSL with ECDSA support on the secp256k1 curve is used for cryptographic operations.
-	Cryptographic primitives are encapsulated and set at the start of the network, with plans to adopt NTRU lattice-based cryptography for quantum resistance.
9.	Deployment:
-	DGT offers two configurations: CORE (under Apache 2.0 license) for private network deployment and GARANASKA (AGL 3.0 license) with advanced features.
-	GARANASKA supports the DGT-MAINNET core network and provides additional functionality for spe-cialized solutions.

This overview provides a concise summary of DGT's architecture, highlighting key components and features. More detailed information can be found in the platform's technical documentation to ensure a compre-hensive understanding of its capabilities. More information available in dgtnetwork.gitbook.io.
