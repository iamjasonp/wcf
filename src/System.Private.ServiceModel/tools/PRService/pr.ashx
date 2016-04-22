 // Copyright (c) Microsoft. All rights reserved.
 // Licensed under the MIT license. See LICENSE file in the project root for full license information.
 
<%@ WebHandler Language="C#" Class="PullRequestHandler" %>

// This script is called to prepare a local repo for testing
// ASSUMES: 
//   - web.config or environment variables are configured with the git executable path, and repo base path
//   - 
//   - The Git repo is set up as follows: 
//     [remote "origin"]
//         url = https://github.com/dotnet/wcf
//         fetch = +refs/heads/*:refs/remotes/origin/*
//         fetch = +refs/pull/*/head:refs/remotes/origin/pr/*      <-- allows us to run git checkout pr/{id} 
//
// We also support checking out branches, and we check the input against the list of branches using 'git branch --list --remote'

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Web;

public class PullRequestHandler : IHttpHandler
{
    private string _gitExecutablePath;
    private string _gitRepositoriesBasePath;
    private TimeSpan _gitExecutionTimeout;

    private bool _configurationRead = false;

    private const string _gitExecutablePathConfigurationKeyString = "GitExecutablePath";
    private const string _gitRepositoriesBasePathConfigurationKeyString = "GitRepositoriesBasePath";
    private const string _gitExecutionTimeoutConfigurationKeyString = "GitExecutionTimeout";

    private const string _gitRepoPathTemplate = @"{0}\wcf{1}";

    public void ProcessRequest(HttpContext context)
    {
        StringBuilder result = new StringBuilder();

        // Read configuration
        bool success = ReadConfiguration(result);
        if (!success)
        {
            // ReadConfiguration failed, this is a server issue 
            context.Response.StatusCode = 500;
            context.Response.Write(HttpUtility.HtmlEncode(result.ToString()));
            return;
        }

        // Check inputs 
        // We expect one of the following to be specified: 
        // - A numerical repo ID
        // - A branch name OR a PR number (not both)
        //
        // We will use Git to validate and verify that the branch exists if specified

        success = false;

        string repoIdString = context.Request.QueryString["id"];
        string branchString = context.Request.QueryString["branch"];
        string prString = context.Request.QueryString["pr"];

        if (string.IsNullOrWhiteSpace(repoIdString) || !ValidateDirectory(repoIdString))
        {
            context.Response.StatusCode = 400;
            context.Response.Write(string.Format("The client ID specified, '{0}', is invalid. Please specify a valid 'id' in the request query string <br/>", repoIdString ?? "unspecified"));
            return;
        }

        if (string.IsNullOrWhiteSpace(prString) && string.IsNullOrWhiteSpace(branchString))
        {
            context.Response.StatusCode = 400;
            context.Response.Write("No PR or branch specified. Specify either a 'pr' or 'branch' in the request query string <br/>");
            return;
        }

        if (!string.IsNullOrWhiteSpace(prString) && !string.IsNullOrWhiteSpace(branchString))
        {
            context.Response.StatusCode = 400;
            context.Response.Write("Both 'pr' and 'branch' specified; please specify only one of them to sync to <br/>");
            return;
        }

        context.Response.Write(string.Format("pr = {0} <br/>", HttpUtility.HtmlEncode(prString) ?? "unspecified"));
        context.Response.Write(string.Format("branch = {0} <br/>", HttpUtility.HtmlEncode(branchString) ?? "unspecified"));

        // Check for prerequisites needed before this script can execute
        string gitRepoPath = GetRepoPath(repoIdString);
        success = CheckPrerequisites(gitRepoPath, result);

        if (!success)
        {
            // CheckPrerequisites failed, this is a server issue
            context.Response.StatusCode = 500;
            context.Response.Write(HttpUtility.HtmlEncode(result.ToString()));
            return;
        }

        // Cleanup all branches except master from the repo - this shouldn't fail, and if it does, there's something wrong with the repo
        success = CleanupBranches(gitRepoPath, result);

        if (!success)
        {
            // CleanupMergedBranches failed, this is a server issue
            context.Response.StatusCode = 500;
            context.Response.Write(HttpUtility.HtmlEncode(result.ToString()));
            return;
        }

        // Do stuff
        success = false;

        uint pr;
        // At this point we are guaranteed to have either a 'pr' or 'branch' but not both
        if (!string.IsNullOrEmpty(prString))
        {
            if (uint.TryParse(prString, out pr))
            {
                success = SyncToPr(pr, gitRepoPath, result);
            }
        }
        else
        {
            // Validate input here, because we don't want someone passing in an arbitrary branch
            // Obtain a list of valid remote branches and allow sync to one of these only

            string[] branches;
            success = GetBranches(gitRepoPath, true, out branches, result);

            if (success)
            {
                success = false;
                for (int i = 0; i < branches.Length; i++)
                {
                    // git branches are case sensitive 
                    if (string.Equals(branchString, branches[i]))
                    {
                        success = SyncToBranch(branchString, gitRepoPath, result);
                        break;
                    }
                }
            }
        }

        if (!success)
        {
            // it's most likely that the client supplied a bad PR ID, but there could potentially 
            // be other errors in SyncToPr or SyncToBranch. For now, return 400 in this path
            context.Response.StatusCode = 400;
            context.Response.Write(string.Format("Invalid 'pr', '{0}' or 'branch', '{1}' specified. Please specify a valid 'pr' or 'branch' <br/>", HttpUtility.HtmlEncode(prString), HttpUtility.HtmlEncode(branchString)));
        }

        context.Response.Write(HttpUtility.HtmlEncode(result.ToString()));
    }

    // Check prerequisites for whether or not we can run
    private bool CheckPrerequisites(string gitRepoPath, StringBuilder executionResult)
    {
        if (!File.Exists(_gitExecutablePath))
        {
            executionResult.AppendFormat("Could not find or insufficient permissions to access the git executable at path '{0}'", _gitExecutablePath);
            return false;
        }

        if (!Directory.Exists(gitRepoPath))
        {
            executionResult.AppendFormat("Could not find or insufficient permissions to access the git repo at path '{0}'", gitRepoPath);
            return false;
        }

        // Do a sanity execute of the git executable 
        bool success = false;

        try
        {
            string[] gitCommands = new string[]
            {
                "status"
            };

            success = RunGitCommands(gitCommands, gitRepoPath, executionResult);
        }
        catch (Exception ex)
        {
            executionResult.AppendFormat("Exception caught while attempting to start '{0}'", _gitExecutablePath);
            executionResult.Append(ex.ToString());
        }

        return success;
    }

    private string GetRepoPath(string repoId)
    {
        // Note: assumes configuration is read. 
        return string.Format(_gitRepoPathTemplate, _gitRepositoriesBasePath, repoId);
    }

    private bool SyncToPr(uint pr, string gitRepoPath, StringBuilder executionResult)
    {
        string[] gitCommands = new string[]
        {
            "clean -fdx",
            "checkout master",
            "fetch --all --prune",
            "merge --ff-only origin/master",
            string.Format("fetch origin pull/{0}/head:pr/{0}", pr),
            string.Format("checkout pr/{0}", pr)
        };

        return RunGitCommands(gitCommands, gitRepoPath, executionResult);
    }

    private bool SyncToBranch(string branch, string gitRepoPath, StringBuilder executionResult)
    {
        string[] gitCommands = new string[]
        {
            "clean -fdx",
            "checkout master",
            "fetch --all --prune",
            "merge --ff-only origin/master",
            string.Format("checkout {0}", branch)
        };

        return RunGitCommands(gitCommands, gitRepoPath, executionResult);
    }

    // Gets a list of branches 
    // - that are available in the repo (remoteBranches == false)
    // - that are available in defined remotes (remoteBranches == true)
    private bool GetBranches(string gitRepoPath, bool remoteBranches, out string[] branches, StringBuilder executionResult)
    {
        bool success = false;
        branches = null;

        StringBuilder branchesString = new StringBuilder();

        if (remoteBranches)
        {
            success = RunGitCommands(new string[] { "branch --remote --list" }, gitRepoPath, branchesString);
        }
        else
        {
            success = RunGitCommands(new string[] { "branch --list" }, gitRepoPath, branchesString);
        }

        executionResult.Append(branchesString);

        if (success)
        {
            branches = branchesString.ToString().Split(new char[] { '\n', '\r', ' ', '*' }, StringSplitOptions.RemoveEmptyEntries);
        }

        return success;
    }

    // Cleans up branches that aren't currently used except "master" from the repo
    // If not done, we'll end up with dozens of branches that aren't used after a while
    // because we don't nuke and re-create the repo after each PR
    private bool CleanupBranches(string gitRepoPath, StringBuilder executionResult)
    {
        bool success = false;

        success = RunGitCommands(new string[] { "checkout master" }, gitRepoPath, executionResult);

        string[] branchesList = null;
        if (success)
        {
            success = GetBranches(gitRepoPath, false, out branchesList, executionResult);
        }

        if (success)
        {
            List<string> commands = new List<string>();

            // we won't get branchesList == null because of the success check
            for (int i = 0; i < branchesList.Length; i++)
            {
                // Don't try to delete "master" branch, since we're checked out to it
                if (!branchesList[i].EndsWith("master"))
                {
                    commands.Add(string.Format("branch -D {0}", branchesList[i]));
                }
            }

            success = RunGitCommands(commands.ToArray(), gitRepoPath, executionResult);
        }

        return success;
    }

    private bool RunGitCommands(string[] gitCommands, string gitRepoPath, StringBuilder executionResult)
    {
        if (gitCommands == null || gitCommands.Length == 0)
        {
            return true;
        }

        ProcessStartInfo psi = new ProcessStartInfo()
        {
            CreateNoWindow = true,
            FileName = _gitExecutablePath,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            WorkingDirectory = gitRepoPath
        };

        bool success = true;

        foreach (string gitCommand in gitCommands)
        {
            success = false;
            psi.Arguments = gitCommand;

            Process p = Process.Start(psi);
            if (!p.WaitForExit((int)_gitExecutionTimeout.TotalMilliseconds))
            {
                executionResult.Append(string.Format("Git executable '{0}' took more than '{1}' to execute <br/>", _gitExecutablePath, _gitExecutionTimeout));
                executionResult.Append(string.Format("Git command was: '{0}' ", gitCommand));

                // return early if !WaitForExit, as p.ExitCode will not be usable in this case (it throws an exception) 
                return success;
            }

            success = p.ExitCode == 0;

            executionResult.Append(p.StandardOutput.ReadToEnd());
            executionResult.Append(p.StandardError.ReadToEnd());

            if (!success)
            {
                executionResult.Append(string.Format("Git executable '{0}' exited with code '{1}', expected '{2}' <br/>", _gitExecutablePath, p.ExitCode, "0"));
                executionResult.Append(string.Format("Git command was: '{0}' ", gitCommand));

                return success;
            }
        }

        return success;
    }

    // Read configuration
    // Precedence is: 
    // 1. Environment variable
    // 2. AppSettings in web.config
    // 
    // returns: successful read of configuration or not
    // errorOutput: passed back to the caller to provide a verbose explanation of what went wrong
    private bool ReadConfiguration(StringBuilder errorOutput)
    {
        if (_configurationRead)
        {
            // No locking needed, reading this in twice, even on multiple concurrent threads, doesn't do harm
            return true;
        }

        NameValueCollection appSettings = ConfigurationManager.AppSettings;

        string gitExecutablePath = Environment.GetEnvironmentVariable(_gitExecutablePathConfigurationKeyString);
        if (string.IsNullOrWhiteSpace(gitExecutablePath))
        {
            gitExecutablePath = appSettings[_gitExecutablePathConfigurationKeyString];
        }
        if (string.IsNullOrWhiteSpace(gitExecutablePath))
        {
            errorOutput.AppendFormat("Invalid or missing {0}: '{1}'", _gitExecutablePathConfigurationKeyString, gitExecutablePath ?? "unspecified");
            return false;
        }

        _gitExecutablePath = gitExecutablePath;

        string gitRepositoriesBasePath = Environment.GetEnvironmentVariable(_gitRepositoriesBasePathConfigurationKeyString);
        if (string.IsNullOrWhiteSpace(gitRepositoriesBasePath))
        {
            gitRepositoriesBasePath = appSettings[_gitRepositoriesBasePathConfigurationKeyString];
        }
        if (string.IsNullOrWhiteSpace(gitRepositoriesBasePath))
        {
            errorOutput.AppendFormat("Invalid or missing {0}: '{1}'", _gitRepositoriesBasePathConfigurationKeyString, gitRepositoriesBasePath ?? "unspecified");
            return false;
        }

        _gitRepositoriesBasePath = gitRepositoriesBasePath;

        string gitExecutionTimeoutString = Environment.GetEnvironmentVariable(_gitExecutionTimeoutConfigurationKeyString);
        if (string.IsNullOrWhiteSpace(gitExecutionTimeoutString))
        {
            gitExecutionTimeoutString = appSettings[_gitExecutionTimeoutConfigurationKeyString];
        }
        if (!string.IsNullOrWhiteSpace(gitRepositoriesBasePath) && !TimeSpan.TryParse(gitExecutionTimeoutString, out _gitExecutionTimeout))
        {
            errorOutput.AppendFormat("Invalid or missing {0}: '{1}'", _gitExecutionTimeoutConfigurationKeyString, gitRepositoriesBasePath ?? "unspecified");
            return false;
        }

        _configurationRead = true;
        return true;
    }

    private bool ValidateDirectory(string directoryName)
    {
        var length = directoryName.Length;

        // Disallow "master" in directory name, it has a special meaning for us
        if (string.Equals(directoryName, "master", StringComparison.OrdinalIgnoreCase)) return false; 

        // Bound the length so we don't try to validate forever
        // This should be long enough for what we need
        if (length > 100) return false;

        // Allow [A-Za-z0-9]*
        for (int i = 0; i < length; i++)
        {
            if (directoryName[i] >= 'a' && directoryName[i] <= 'z') continue;
            if (directoryName[i] >= 'A' && directoryName[i] <= 'Z') continue;
            if (directoryName[i] >= '0' && directoryName[i] <= '9') continue;
            return false;
        }

        return true;
    }

    public bool IsReusable
    {
        get
        {
            return false;
        }
    }
}
