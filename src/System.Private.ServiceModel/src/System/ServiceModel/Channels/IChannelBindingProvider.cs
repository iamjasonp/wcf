// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace System.ServiceModel.Channels
{
    using System;
    using System.Security.Authentication.ExtendedProtection;

    interface IChannelBindingProvider
    {
        void EnableChannelBindingSupport();
        bool IsChannelBindingSupportEnabled { get; }
    }
}