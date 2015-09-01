// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.ServiceModel;
using System.Text;
using Xunit;

public static class Tcp_ClientCredentialTypeTests
{
    // Simple echo of a string using NetTcpBinding on both client and server with all default settings.
    // Default settings means SecurityMode is set to Transport.
    [Fact]
    [OuterLoop]
    public static void SameBinding_DefaultSettings_EchoString()
    {
        string variationDetails = "Client:: NetTcpBinding/DefaultValues\nServer:: NetTcpBinding/DefaultValues";
        string testString = "Hello";
        StringBuilder errorBuilder = new StringBuilder();
        bool success = false;

        try
        {
            NetTcpBinding binding = new NetTcpBinding();

            binding.SendTimeout = TimeSpan.FromMinutes(60);
            binding.ReceiveTimeout = TimeSpan.FromMinutes(90);
            binding.OpenTimeout = TimeSpan.FromMinutes(120);
            binding.CloseTimeout = TimeSpan.FromMinutes(180);

            ChannelFactory<IWcfService> factory = new ChannelFactory<IWcfService>(binding, new EndpointAddress(Endpoints.Tcp_DefaultBinding_Address));
            IWcfService serviceProxy = factory.CreateChannel();

            string result = serviceProxy.Echo(testString);
            success = string.Equals(result, testString);

            if (!success)
            {
                errorBuilder.AppendLine(String.Format("    Error: expected response from service: '{0}' Actual was: '{1}'", testString, result));
            }
        }
        catch (Exception ex)
        {
            errorBuilder.AppendLine(String.Format("    Error: Unexpected exception was caught while doing the basic echo test for variation...\n'{0}'\nException: {1}", variationDetails, ex.ToString()));
            for (Exception innerException = ex.InnerException; innerException != null; innerException = innerException.InnerException)
            {
                errorBuilder.AppendLine(String.Format("Inner exception: {0}", innerException.ToString()));
            }
        }

        Assert.True(errorBuilder.Length == 0, "Test case FAILED with errors: " + errorBuilder.ToString());
    }

    // Simple echo of a string using NetTcpBinding on both client and server with all default settings.
    //[Fact]
    [ActiveIssue(81)]
    [OuterLoop]
    public static void SameBinding_SecurityModeNone_EchoString()
    {
        string variationDetails = "Client:: NetTcpBinding/SecurityMode = None\nServer:: NetTcpBinding/SecurityMode = None";
        string testString = "Hello";
        StringBuilder errorBuilder = new StringBuilder();
        bool success = false;

        try
        {
            NetTcpBinding binding = new NetTcpBinding(SecurityMode.None);
            ChannelFactory<IWcfService> factory = new ChannelFactory<IWcfService>(binding, new EndpointAddress(Endpoints.Tcp_NoSecurity_Address));
            IWcfService serviceProxy = factory.CreateChannel();

            string result = serviceProxy.Echo(testString);
            success = string.Equals(result, testString);

            if (!success)
            {
                errorBuilder.AppendLine(String.Format("    Error: expected response from service: '{0}' Actual was: '{1}'", testString, result));
            }
        }
        catch (Exception ex)
        {
            errorBuilder.AppendLine(String.Format("    Error: Unexpected exception was caught while doing the basic echo test for variation...\n'{0}'\nException: {1}", variationDetails, ex.ToString()));
            for (Exception innerException = ex.InnerException; innerException != null; innerException = innerException.InnerException)
            {
                errorBuilder.AppendLine(String.Format("Inner exception: {0}", innerException.ToString()));
            }
        }

        Assert.True(errorBuilder.Length == 0, "Test case FAILED with errors: " + errorBuilder.ToString());
    }

    // Simple echo of a string using NetTcpBinding on both client and server with SecurityMode=Transport
    //[Fact]
    [ActiveIssue(81)]
    [OuterLoop]
    public static void SameBinding_SecurityModeTransport_EchoString()
    {
        string variationDetails = "Client:: NetTcpBinding/SecurityMode = Transport\nServer:: NetTcpBinding/SecurityMode = Transport";
        string testString = "Hello";
        StringBuilder errorBuilder = new StringBuilder();
        bool success = false;

        try
        {
            NetTcpBinding binding = new NetTcpBinding(SecurityMode.Transport);
            ChannelFactory<IWcfService> factory = new ChannelFactory<IWcfService>(binding, new EndpointAddress(Endpoints.Tcp_NoSecurity_Address));
            IWcfService serviceProxy = factory.CreateChannel();

            string result = serviceProxy.Echo(testString);
            success = string.Equals(result, testString);

            if (!success)
            {
                errorBuilder.AppendLine(String.Format("    Error: expected response from service: '{0}' Actual was: '{1}'", testString, result));
            }
        }
        catch (Exception ex)
        {
            errorBuilder.AppendLine(String.Format("    Error: Unexpected exception was caught while doing the basic echo test for variation...\n'{0}'\nException: {1}", variationDetails, ex.ToString()));
            for (Exception innerException = ex.InnerException; innerException != null; innerException = innerException.InnerException)
            {
                errorBuilder.AppendLine(String.Format("Inner exception: {0}", innerException.ToString()));
            }
        }

        Assert.True(errorBuilder.Length == 0, "Test case FAILED with errors: " + errorBuilder.ToString());
    }
}
