// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace System.ServiceModel.Channels
{
    using System.IO;
    using System.ServiceModel.Security;

    public abstract class StreamSecurityUpgradeAcceptor : StreamUpgradeAcceptor
    {
        protected StreamSecurityUpgradeAcceptor()
        {
        }

        public abstract SecurityMessageProperty GetRemoteSecurity(); // works after call to AcceptUpgrade
    }
}
