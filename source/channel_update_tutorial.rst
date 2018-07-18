添加一个组织（Org）到通道（Channel）中
==========================

.. note:: 确认你已经下载了在 :doc:`samples` 和 :doc:`prereqs` 中列出来的和当前文档版本
          （位于左侧目录栏底部）匹配的相应镜像(images)和二进制文件。特别是，你的
          ``fabric-samples`` 版本的文件夹中必须有 ``eyfn.sh`` 脚本和起相关的脚本。

本教程是基于 :doc:`build_network` (BYFN) 教程，将演示如何增加一个新的组织 -- ``Org3`` -- 
到由BYFN自动生成的程序通道（``mychannel``）。假定你已经非常明白BYFN，包括前面提及到的工具
使用和功能。

虽然这里我们只是聚焦于新组织的集成，但同样的方法适用于完成其他通道配置更新（例如：更新修改
策略或者改变批量大小）。 学习更多关于通道配置总体更新的过程和可能性，请参考 :doc:`config_update` 。
像这里演示的通道配置更新通常是一个组织管理员（而不是链码或者程序开发者）的职责也是不足为奇了。

.. note:: 在继续之前，请确认自动化脚本 ``byfn.sh`` 在你的机器上运行没有错误。如果你已经在你的
          系统PATH变量中包含了你的二进制文件和相关的工具（``cryptogen``, ``configtxgen`` 等），
          你可以对一些命令做相应的修改，无需传入完整的路径。

设置环境
~~~~~~~~~~~~~~~~~~~~~

我们将从你本地克隆的 ``fabric-samples`` 子目录 ``first-network`` 开始操作。现在进到该目录，
为了操作方便，建议你打开几个新的控制台。

首先，使用脚本 ``byfn.sh`` 做初始化准备。这个命令将杀掉所有的活跃和非活跃状态的docker容器，
同事删除之前自动生成的artifacts目录中的内容。为了完成通道（Channel）配置更新任务，绝对
**没必要** 停止Fabric网络。但是，为了本教程的目的，我们想从一个大家都熟悉的初始化状态开始操作。
因此，请执行下面的命令，用来清理之前的环境变量：

.. code:: bash

  ./byfn.sh -m down

现在产生默认的BYFN 一些必要的文件在artifacts目录：

.. code:: bash

  ./byfn.sh -m generate

然后在CLI容器中利用下面的脚本来启动网络：

.. code:: bash

  ./byfn.sh -m up

现在在你的机器上运行一个干净的BYFN版本，你有两个不同的方式可以继续进行。首先，我们提供一个
有详细注解的脚本文件用来执行一个配置事务更新，使得把Org3加入到网络中来。

其次，我们也会展示一个同样操作流程的“手动”版本，显示每一步操作并解释其做了什么（在这个手动
操作之前我们会向你演示停止你的Fabric网络，你也可以运行该脚本然后观察你每一步）

用脚本把Org3加入到通道
~~~~~~~~~~~~~~~~~~~~~~~

进入到目录 ``first-network`` 。要使用该脚本，只需要简单执行下面的命令:

.. code:: bash

  ./eyfn.sh up

该脚本的输出内容应该仔细阅读一下。你将会看到正在添加Org3的加密资料，正在创建并签名配置更新，
然后正在安装用来允许Org3执行账本查询的链码。

如果一切进展顺利，你将会看到这样的消息：

.. code:: bash

  ========= All GOOD, EYFN test execution completed ===========

通过执行下面的命令（不是 ``./byfn.sh -m -up` ）， ``eyfn.sh`` 也可以选择执行相同的Node.js
版本的链码，也可以传递数据库参数给 ``byfn.sh`` :

.. code:: bash

  ./byfn.sh up -c testchannel -s couchdb -l node

然后执行:

.. code:: bash

  ./eyfn.sh up -c testchannel -s couchdb -l node

对于那些需要进一步了解这个过程的读者来说，本文档接下来将向你展示用来完成一个通道更新的每一个
命令以及该命令做了什么。

手动把Org3加入到通道中
~~~~~~~~~~~~~~~~~~~~~~~

.. note:: 下面列出来的手动操作步骤前提条件是 ``cli`` 和 `Org3cli`` 容器的
          ``CORE_LOGGING_LEVEL`` 被设置为 ``DEBUG``。

          对 ``cli`` 容器，你可以通过修改在 ``first-network`` 目录中的 
          ``docker-compose-cli.yaml`` 文件来设置它。
          例如：

          .. code::

            cli:
              container_name: cli
              image: hyperledger/fabric-tools:$IMAGE_TAG
              tty: true
              stdin_open: true
              environment:
                - GOPATH=/opt/gopath
                - CORE_VM_ENDPOINT=unix:///host/var/run/docker.sock
                #- CORE_LOGGING_LEVEL=INFO
                - CORE_LOGGING_LEVEL=DEBUG

          对 ``Org3cli`` 容器，你可以通过修改在 ``first-network`` 目录中的 
          ``docker-compose-org3.yaml`` 文件来设置它。
          例如：

          .. code::

            Org3cli:
              container_name: Org3cli
              image: hyperledger/fabric-tools:$IMAGE_TAG
              tty: true
              stdin_open: true
              environment:
                - GOPATH=/opt/gopath
                - CORE_VM_ENDPOINT=unix:///host/var/run/docker.sock
                #- CORE_LOGGING_LEVEL=INFO
                - CORE_LOGGING_LEVEL=DEBUG

如果你之前已经执行过 ``eyfn.sh`` 脚本，那么你需要先停掉Fabric网络。
这个可以通过执行以下命令完成：

.. code:: bash

  ./eyfn.sh down

这将停止Fabric网络，删除所有的容器(Fabric容器，译者注)，以及回撤增加Org3的所有操作。

当网络停止，再重启启动它。

.. code:: bash

  ./byfn.sh -m generate

然后:

.. code:: bash

  ./byfn.sh -m up

这样你的网络又恢复到执行 ``eyfn.sh`` 脚本之前的同样状态了。

现在你可以开始手动添加Org3了。第一步，你得先生成Org3的加密资料。

生成Org3加密资料
~~~~~~~~~~~~~~~~~~

开启另外一个终端，从 ``first-network`` 进入到 ``org3-artifacts`` 子目录中。

.. code:: bash

  cd org3-artifacts

那里有两个我们需要关注的 ``yaml`` 文件： ``org3-crypto.yaml`` 和 ``configtx.yaml`` 。
首先，为Org3生成加密资料：

.. code:: bash

  ../../bin/cryptogen generate --config=./org3-crypto.yaml

该命令读取我们新的加密 ``yaml`` 文件 -- ``org3-crypto.yaml`` -- ，然后利用 ``cryptogen`` 
为Org3 CA生成密钥和证书，而且生成两个节点（peer）归属于这个新的Org（组织）。根据BYFN实现，
这些加密资料放在当前所在目录的一个新建的 ``crypto-config`` 文件夹中（在本例子中是 ``org3-artifacts`` ）。

现在使用 ``configtxgen`` 工具打印出Org3专用的JSON格式配置材料。 在开始该命令之前，我们得告诉它
需要从当前目录来读取 ``configtx.yaml`` 文件（该工具需要用的的配置信息文件，译者注）。

.. code:: bash

    export FABRIC_CFG_PATH=$PWD && ../../bin/configtxgen -printOrg Org3MSP > ../channel-artifacts/org3.json

上面命令会创建一个JSON文件 -- ``org3.json`` -- 同时把它写到 ``first-network`` 根路径下面的
``channel-artifacts`` 子目录。 这个文件包括Org3的策略定义，以及三个重要的以base64格式呈现的证书：
管理员用户证书（将来需要用来充当Org3的管理员）， 一个CA根证书，以及一个TLS根证书。在接下来一步，
我们将给通道配置附上这个JSON文件。

我们最终的内务处理块将携带排序组织（Orderer Org）的MSP资料到Org3的 ``crypto-config`` 目录中。
特别是，我们关心的Orderer的TLS根证书，是用来在Org3实体和网络的排序节点之间保障安全通讯的。

.. code:: bash

  cd ../ && cp -r crypto-config/ordererOrganizations org3-artifacts/crypto-config/

现在我们准备更新通道配置...

准备CLI环境
~~~~~~~~~~~~

更新处理过程使用配置解析工具 -- ``configtxlator`` 。这工具提供一个不依赖SDK的无状态的REST API。
另外还提供一个CLI，用来在Fabric网络中简化配置任务。该工具可以方便在不同的等价数据表现/格式之间
（在本例中是protobuf和JSON格式， Google Protocol Buffer简称protobuf，译者注）进行转换。另外，
该工具可以基于两个通道配置之间的差异计算一个配置更新事务。

首先，通过exec命令进入CLI容器。回想一下该容器已经被BYFN ``crypto-config`` 库程序加载，其允许我们
访问两个原始节点组织和排序组织（Orderer Org）的MSP资料。引导身份是Org1的管理员，意味着我们想作为
Org2的任何一步操作都需要MSP明确的环境变量输出。

.. code:: bash

  docker exec -it cli bash

现在安装 ``jq`` 工具到容器中。该工具允许与由 ``configtxlator`` 工具返回的JSON文件进行脚本交互：

.. code:: bash

  apt update && apt install -y jq

Export出 ``ORDERER_CA`` 和 ``CHANNEL_NAME`` 变量:

.. code:: bash

  export ORDERER_CA=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem  && export CHANNEL_NAME=mychannel

检查确认变量已经被正确设置：

.. code:: bash

  echo $ORDERER_CA && echo $CHANNEL_NAME

.. note:: 如果因为任何原因你需要重启CLI容器，你也需要重新Export出两个环境变量 -- ``ORDERER_CA`` 
          和 ``CHANNEL_NAME`` 。jq安装会保留，无需再次安装它。

读取配置
~~~~~~~~~

现在我们已经在CLI容器中定义好了两个变量 -- ``ORDERER_CA`` 和 ``CHANNEL_NAME`` 。咱们开始读取
最新的通道（ ``mychannel`` ）配置区块。

之所以我们拿最新版本的配置，是因为通道配置元素是版本区分的。版本化在几个方面表现很重要。首先，版本化防
止配置更新重复或者重现（例如：回退一个使用旧的CRL的通道配置意味着安全风险）。 其次，版本化帮助确保并发（例
如：在添加了一个新的组织Org之后，如果你想从你的通道中删除一个组织Org，版本化将帮助你防止一起删除这两个
组织Org，而是只删除你想要删除的那个组织Org）。

.. code:: bash

  peer channel fetch config config_block.pb -o orderer.example.com:7050 -c $CHANNEL_NAME --tls --cafile $ORDERER_CA

该命令保存二进制protobuf通道配置区块到 ``config_block.pb`` 文件。注意，你可以随意输入文件名和扩张名。
但是，建议遵循一个约定：其方便识别文件数据类型和编码格式（protobuf或者JSON）。

当你运行 ``peer channel fetch`` 命令，在终端会有大量输出，日志中最后一行需要关注的是：

.. code:: bash

  2017-11-07 17:17:57.383 UTC [channelCmd] readBlock -> DEBU 011 Received block: 2

这行日志告诉我们最新的 ``mychannel`` 配置区块实际上是区块2，**不是** 初始区块。默认情况下，
``peer channel fetch config`` 命令返回指定通道的最 **新** 配置区块，在本例中是第三个区块。
这是因为BYFN脚本为 ``Org1`` 和 ``Org2`` 两个组织（在两个单独的通道更新交易）定义了锚节点。

结果，我们有下列配置序列：

  * 区块 0: 初始区块
  * 区块 1: Org1锚节点更新
  * 区块 2: Org2锚节点更新

转换配置内容到JSON格式，然后裁剪
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

现在我们使用 ``configtxlator`` 工具来解码通道配置区块成JSON格式（我们可以读和修改的格式）
我们也必须去掉所有的header、metadata、创建者签名等和我们需要做的修改不相关的内容。我们通
过 ``jq`` 工具来完成该操作：

.. code:: bash

  configtxlator proto_decode --input config_block.pb --type common.Block | jq .data.data[0].payload.data.config > config.json

这会给我们生成一个裁剪后的JSON对象 -- ``config.json`` ，被放在 ``first-network`` 目录
下 ``fabric-samples`` 的文件夹中（其将用作我们配置更新的基准）。

花一点时间在文件编辑器中打开这个文件（也可以在浏览器中打开）。即使你已经学习完该教材，也还
是值得去研究一下它，因为它解析了基础配置架构以及可以实施的其通道更新操作。我们会在
:doc:`config_update` 中详细地讨论这些。

添加Org3的加密资料
~~~~~~~~~~~~~~~~~~

.. note:: 不管你做哪种配置更新，你执行的步骤到目前为止基本上都是相同的。 在本教程，我们之
          所以选择增加一个组织，因为这是你可以尝试操作的最复杂的通道配置更新。

我们将再次使用 ``jq`` 工具来添加Org3的配置定义 -- ``org3.json`` -- 到通道的程序组域，然
后输出到文件 -- ``modified_config.json`` 。

.. code:: bash

  jq -s '.[0] * {"channel_group":{"groups":{"Application":{"groups": {"Org3MSP":.[1]}}}}}' config.json ./channel-artifacts/org3.json > modified_config.json

现在，在CLI容器中我们有两个需要关注的文件 -- ``config.json`` 和 ``modified_config.json`` 。
初始文件内容只包括Org1和Org2资料，但是“修改后”的文件包括三个组织Org。在这一步，这是对两个JSON
文件做一个简单的重新编码，计算方差。

首先，翻译 ``config.json`` 成一个protobuf文件，文件名为 ``config.pb``:

.. code:: bash

  configtxlator proto_encode --input config.json --type common.Config --output config.pb

接下来，编码 ``modified_config.json`` 成 ``modified_config.pb``:

.. code:: bash

  configtxlator proto_encode --input modified_config.json --type common.Config --output modified_config.pb

现在使用 ``configtxlator`` 来计算这两个配置protobuf文件直接的方差delta。该命令将输入一个新的
protobuf二进制文件叫 ``org3_update.pb``:

.. code:: bash

  configtxlator compute_update --channel_id $CHANNEL_NAME --original config.pb --updated modified_config.pb --output org3_update.pb

这个新的proto文件 -- ``org3_update.pb`` -- 包含Org3定义和高标准关联指向Org1和Org2资料。
我们可以先不去想大量MSP资料和对Org1和Org2的修改策略信息，因为这个数据已经在通道的初始区块中展示
了。同样，我们只需要这两个配置之间的方差。

在提交通道更新之前，我们需要完成最后几步。首先，让我们解码一下这个对象成可编辑的JSON格式并取名
为 ``org3_update.json``:

.. code:: bash

  configtxlator proto_decode --input org3_update.pb --type common.ConfigUpdate | jq . > org3_update.json

现在，我们有一个解码后的更新文件 -- ``org3_update.json`` -- 我们需要把它装入一个信封消息。
这一步将给回我们在之前去掉的header信息。我们取名这个文件叫 ``org3_update_in_envelope.json``:

.. code:: bash

  echo '{"payload":{"header":{"channel_header":{"channel_id":"mychannel", "type":2}},"data":{"config_update":'$(cat org3_update.json)'}}}' | jq . > org3_update_in_envelope.json

Using our properly formed JSON -- ``org3_update_in_envelope.json`` -- we will
leverage the ``configtxlator`` tool one last time and convert it into the
fully fledged protobuf format that Fabric requires. We'll name our final update
object ``org3_update_in_envelope.pb``:

.. code:: bash

  configtxlator proto_encode --input org3_update_in_envelope.json --type common.Envelope --output org3_update_in_envelope.pb

Sign and Submit the Config Update
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Almost done!

We now have a protobuf binary -- ``org3_update_in_envelope.pb`` -- within
our CLI container. However, we need signatures from the requisite Admin users
before the config can be written to the ledger. The modification policy (mod_policy)
for our channel Application group is set to the default of "MAJORITY", which means that
we need a majority of existing org admins to sign it. Because we have only two orgs --
Org1 and Org2 -- and the majority of two is two, we need both of them to sign. Without
both signatures, the ordering service will reject the transaction for failing to
fulfill the policy.

First, let's sign this update proto as the Org1 Admin. Remember that the CLI container
is bootstrapped with the Org1 MSP material, so we simply need to issue the
``peer channel signconfigtx`` command:

.. code:: bash

  peer channel signconfigtx -f org3_update_in_envelope.pb

The final step is to switch the CLI container's identity to reflect the Org2 Admin
user. We do this by exporting four environment variables specific to the Org2 MSP.

.. note:: Switching between organizations to sign a config transaction (or to do anything
          else) is not reflective of a real-world Fabric operation. A single container
          would never be mounted with an entire network's crypto material. Rather, the
          config update would need to be securely passed out-of-band to an Org2
          Admin for inspection and approval.

Export the Org2 environment variables:

.. code:: bash

  # you can issue all of these commands at once

  export CORE_PEER_LOCALMSPID="Org2MSP"

  export CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt

  export CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp

  export CORE_PEER_ADDRESS=peer0.org2.example.com:7051

Lastly, we will issue the ``peer channel update`` command. The Org2 Admin signature
will be attached to this call so there is no need to manually sign the protobuf a
second time:

.. note:: The upcoming update call to the ordering service will undergo a series
          of systematic signature and policy checks. As such you may find it
          useful to stream and inspect the ordering node's logs. From another shell,
          issue a ``docker logs -f orderer.example.com`` command to display them.

Send the update call:

.. code:: bash

  peer channel update -f org3_update_in_envelope.pb -c $CHANNEL_NAME -o orderer.example.com:7050 --tls --cafile $ORDERER_CA

You should see a message digest indication similar to the following if your
update has been submitted successfully:

.. code:: bash

  2018-02-24 18:56:33.499 UTC [msp/identity] Sign -> DEBU 00f Sign: digest: 3207B24E40DE2FAB87A2E42BC004FEAA1E6FDCA42977CB78C64F05A88E556ABA

You will also see the submission of our configuration transaction:

.. code:: bash

  2018-02-24 18:56:33.499 UTC [channelCmd] update -> INFO 010 Successfully submitted channel update

The successful channel update call returns a new block -- block 5 -- to all of the
peers on the channel. If you remember, blocks 0-2 are the initial channel
configurations while blocks 3 and 4 are the instantiation and invocation of
the ``mycc`` chaincode. As such, block 5 serves as the most recent channel
configuration with Org3 now defined on the channel.

Inspect the logs for ``peer0.org1.example.com``:

.. code:: bash

      docker logs -f peer0.org1.example.com

Follow the demonstrated process to fetch and decode the new config block if you wish to inspect
its contents.

Configuring Leader Election
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. note:: This section is included as a general reference for understanding
          the leader election settings when adding organizations to a network
          after the initial channel configuration has completed. This sample
          defaults to dynamic leader election, which is set for all peers in the
          network in `peer-base.yaml`.

Newly joining peers are bootstrapped with the genesis block, which does not
contain information about the organization that is being added in the channel
configuration update. Therefore new peers are not able to utilize gossip as
they cannot verify blocks forwarded by other peers from their own organization
until they get the configuration transaction which added the organization to the
channel. Newly added peers must therefore have one of the following
configurations so that they receive blocks from the ordering service:

1. To utilize static leader mode, configure the peer to be an organization
leader:

::

    CORE_PEER_GOSSIP_USELEADERELECTION=false
    CORE_PEER_GOSSIP_ORGLEADER=true


.. note:: This configuration must be the same for all new peers added to the
channel.

2. To utilize dynamic leader election, configure the peer to use leader
election:

::

    CORE_PEER_GOSSIP_USELEADERELECTION=true
    CORE_PEER_GOSSIP_ORGLEADER=false


.. note:: Because peers of the newly added organization won't be able to form
          membership view, this option will be similar to the static
          configuration, as each peer will start proclaiming itself to be a
          leader. However, once they get updated with the configuration
          transaction that adds the organization to the channel, there will be
          only one active leader for the organization. Therefore, it is
          recommended to leverage this option if you eventually want the
          organization's peers to utilize leader election.


Join Org3 to the Channel
~~~~~~~~~~~~~~~~~~~~~~~~

At this point, the channel configuration has been updated to include our new
organization -- ``Org3`` -- meaning that peers attached to it can now join ``mychannel``.

First, let's launch the containers for the Org3 peers and an Org3-specific CLI.

Open a new terminal and from ``first-network`` kick off the Org3 docker compose:

.. code:: bash

  docker-compose -f docker-compose-org3.yaml up -d

This new compose file has been configured to bridge across our initial network,
so the two peers and the CLI container will be able to resolve with the existing
peers and ordering node. With the three new containers now running, exec into
the Org3-specific CLI container:

.. code:: bash

  docker exec -it Org3cli bash

Just as we did with the initial CLI container, export the two key environment
variables: ``ORDERER_CA`` and ``CHANNEL_NAME``:

.. code:: bash

  export ORDERER_CA=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem && export CHANNEL_NAME=mychannel

Check to make sure the variables have been properly set:

.. code:: bash

  echo $ORDERER_CA && echo $CHANNEL_NAME

Now let's send a call to the ordering service asking for the genesis block of
``mychannel``. The ordering service is able to verify the Org3 signature
attached to this call as a result of our successful channel update. If Org3
has not been successfully appended to the channel config, the ordering
service should reject this request.

.. note:: Again, you may find it useful to stream the ordering node's logs
          to reveal the sign/verify logic and policy checks.

Use the ``peer channel fetch`` command to retrieve this block:

.. code:: bash

  peer channel fetch 0 mychannel.block -o orderer.example.com:7050 -c $CHANNEL_NAME --tls --cafile $ORDERER_CA

Notice, that we are passing a ``0`` to indicate that we want the first block on
the channel's ledger (i.e. the genesis block). If we simply passed the
``peer channel fetch config`` command, then we would have received block 5 -- the
updated config with Org3 defined. However, we can't begin our ledger with a
downstream block -- we must start with block 0.

Issue the ``peer channel join`` command and pass in the genesis block -- ``mychannel.block``:

.. code:: bash

  peer channel join -b mychannel.block

If you want to join the second peer for Org3, export the ``TLS`` and ``ADDRESS`` variables
and reissue the ``peer channel join command``:

.. code:: bash

  export CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/peerOrganizations/org3.example.com/peers/peer1.org3.example.com/tls/ca.crt && export CORE_PEER_ADDRESS=peer1.org3.example.com:7051

  peer channel join -b mychannel.block

Upgrade and Invoke Chaincode
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The final piece of the puzzle is to increment the chaincode version and update
the endorsement policy to include Org3. Since we know that an upgrade is coming,
we can forgo the futile exercise of installing version 1 of the chaincode. We
are solely concerned with the new version where Org3 will be part of the
endorsement policy, therefore we'll jump directly to version 2 of the chaincode.

From the Org3 CLI:

.. code:: bash

  peer chaincode install -n mycc -v 2.0 -p github.com/chaincode/chaincode_example02/go/

Modify the environment variables accordingly and reissue the command if you want to
install the chaincode on the second peer of Org3. Note that a second installation is
not mandated, as you only need to install chaincode on peers that are going to serve as
endorsers or otherwise interface with the ledger (i.e. query only). Peers will
still run the validation logic and serve as committers without a running chaincode
container.

Now jump back to the **original** CLI container and install the new version on the
Org1 and Org2 peers. We submitted the channel update call with the Org2 admin
identity, so the container is still acting on behalf of ``peer0.org2``:

.. code:: bash

  peer chaincode install -n mycc -v 2.0 -p github.com/chaincode/chaincode_example02/go/

Flip to the ``peer0.org1`` identity:

.. code:: bash

  export CORE_PEER_LOCALMSPID="Org1MSP"

  export CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt

  export CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp

  export CORE_PEER_ADDRESS=peer0.org1.example.com:7051

And install again:

.. code:: bash

  peer chaincode install -n mycc -v 2.0 -p github.com/chaincode/chaincode_example02/go/

Now we're ready to upgrade the chaincode. There have been no modifications to
the underlying source code, we are simply adding Org3 to the endorsement policy for
a chaincode -- ``mycc`` -- on ``mychannel``.

.. note:: Any identity satisfying the chaincode's instantiation policy can issue
          the upgrade call. By default, these identities are the channel Admins.

Send the call:

.. code:: bash

  peer chaincode upgrade -o orderer.example.com:7050 --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA -C $CHANNEL_NAME -n mycc -v 2.0 -c '{"Args":["init","a","90","b","210"]}' -P "OR ('Org1MSP.peer','Org2MSP.peer','Org3MSP.peer')"

You can see in the above command that we are specifying our new version by means
of the ``v`` flag. You can also see that the endorsement policy has been modified to
``-P "OR ('Org1MSP.peer','Org2MSP.peer','Org3MSP.peer')"``, reflecting the
addition of Org3 to the policy. The final area of interest is our constructor
request (specified with the ``c`` flag).

As with an instantiate call, a chaincode upgrade requires usage of the ``init``
method. **If** your chaincode requires arguments be passed to the ``init`` method,
then you will need to do so here.

The upgrade call adds a new block -- block 6 -- to the channel's ledger and allows
for the Org3 peers to execute transactions during the endorsement phase. Hop
back to the Org3 CLI container and issue a query for the value of ``a``. This will
take a bit of time because a chaincode image needs to be built for the targeted peer,
and the container needs to start:

.. code:: bash

    peer chaincode query -C $CHANNEL_NAME -n mycc -c '{"Args":["query","a"]}'

We should see a response of ``Query Result: 90``.

Now issue an invocation to move ``10`` from ``a`` to ``b``:

.. code:: bash

    peer chaincode invoke -o orderer.example.com:7050  --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA -C $CHANNEL_NAME -n mycc -c '{"Args":["invoke","a","b","10"]}'

Query one final time:

.. code:: bash

    peer chaincode query -C $CHANNEL_NAME -n mycc -c '{"Args":["query","a"]}'

We should see a response of ``Query Result: 80``, accurately reflecting the
update of this chaincode's world state.

Conclusion
~~~~~~~~~~

The channel configuration update process is indeed quite involved, but there is a
logical method to the various steps. The endgame is to form a delta transaction object
represented in protobuf binary format and then acquire the requisite number of admin
signatures such that the channel configuration update transaction fulfills the channel's
modification policy.

The ``configtxlator`` and ``jq`` tools, along with the ever-growing ``peer channel``
commands, provide us with the functionality to accomplish this task.

.. Licensed under Creative Commons Attribution 4.0 International License
   https://creativecommons.org/licenses/by/4.0/
