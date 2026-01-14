import 'dotenv/config';
import express from 'express';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { Octokit } from '@octokit/rest';
import Anthropic from '@anthropic-ai/sdk';

const app = express();

// Load environment variables
const {
  GITHUB_APP_ID,
  GITHUB_PRIVATE_KEY,
  GITHUB_WEBHOOK_SECRET,
  ANTHROPIC_API_KEY,
  PORT = 3000
} = process.env;

// Validate required environment variables
if (!GITHUB_APP_ID || !GITHUB_PRIVATE_KEY || !GITHUB_WEBHOOK_SECRET || !ANTHROPIC_API_KEY) {
  console.error('Missing required environment variables');
  process.exit(1);
}

// Initialize Anthropic client
const anthropic = new Anthropic({
  apiKey: ANTHROPIC_API_KEY
});

// Middleware to parse JSON body
app.use(express.json());

/**
 * Verify GitHub webhook signature
 */
function verifySignature(payload, signature) {
  if (!signature) {
    return false;
  }

  const hmac = crypto.createHmac('sha256', GITHUB_WEBHOOK_SECRET);
  const digest = 'sha256=' + hmac.update(JSON.stringify(payload)).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(digest));
}

/**
 * Generate JWT for GitHub App authentication
 */
function generateJWT() {
  const now = Math.floor(Date.now() / 1000);
  return jwt.sign(
    {
      iat: now - 60, // Issued at time (1 minute ago to account for clock skew)
      exp: now + 600, // Expires in 10 minutes
      iss: GITHUB_APP_ID // GitHub App ID (required for GitHub App JWT)
    },
    GITHUB_PRIVATE_KEY.replace(/\\n/g, '\n'),
    { algorithm: 'RS256' }
  );
}

/**
 * Get installation access token
 */
async function getInstallationToken(installationId) {
  const token = generateJWT();
  const octokit = new Octokit({
    auth: token
  });

  const { data } = await octokit.rest.apps.createInstallationAccessToken({
    installation_id: installationId
  });

  return data.token;
}

/**
 * Read guidelines file from repository
 */
async function readGuidelines(octokit, owner, repo) {
  const paths = ['.ai/guidelines.md', '.github/ai-guidelines.md'];

  for (const path of paths) {
    try {
      const { data } = await octokit.rest.repos.getContent({
        owner,
        repo,
        path
      });

      if (data.type === 'file' && data.encoding === 'base64') {
        return Buffer.from(data.content, 'base64').toString('utf-8');
      }
    } catch (error) {
      // File not found, continue to next path
      if (error.status !== 404) {
        console.error(`Error reading guidelines from ${path}:`, error.message);
      }
    }
  }

  return null;
}

/**
 * Get a shallow repository tree (directories + files up to depth 3)
 * This is meant for orientation, not full enumeration.
 */
async function getFileTree(octokit, owner, repo, maxDepth = 3) {
  try {
    // 1. Get repo to discover default branch
    const { data: repoData } = await octokit.rest.repos.get({
      owner,
      repo
    });

    const defaultBranch = repoData.default_branch;

    // 2. Get the commit SHA of the default branch
    const { data: refData } = await octokit.rest.git.getRef({
      owner,
      repo,
      ref: `heads/${defaultBranch}`
    });

    // 3. Get the full tree once
    const { data: treeData } = await octokit.rest.git.getTree({
      owner,
      repo,
      tree_sha: refData.object.sha,
      recursive: '1'
    });

    /**
     * Reduce paths to a shallow, folder-oriented view.
     * Example output:
     * - frontend/
     *   - app/
     *     - layout.tsx
     * - backend/
     *   - src/
     *     - main.ts
     */
    const shallowPaths = new Set();

    for (const item of treeData.tree) {
      if (item.type !== 'blob') continue;

      const parts = item.path.split('/');

      const limitedPath = parts.slice(0, maxDepth).join('/');

      shallowPaths.add(limitedPath);
    }

    return Array.from(shallowPaths).sort();
  } catch (error) {
    console.error('Error fetching file tree:', error.message);
    return [];
  }
}

/**
 * Read multiple files from repo in batch with limits
 */
async function readFilesBatch(octokit, owner, repo, paths, maxFiles = 5, maxBytes = 200_000) {
  const results = [];
  let usedBytes = 0;

  for (const path of paths.slice(0, maxFiles)) {
    try {
      const { data } = await octokit.rest.repos.getContent({ owner, repo, path });

      if (data.type !== 'file' || data.encoding !== 'base64') continue;

      const content = Buffer.from(data.content, 'base64').toString('utf-8');
      const size = Buffer.byteLength(content, 'utf-8');

      if (usedBytes + size > maxBytes) break;

      usedBytes += size;
      results.push({ path, content });
    } catch (error) {
      if (error.status !== 404) {
        console.error(`Error reading file ${path}:`, error.message);
      }
    }
  }

  return results;
}

async function createWorkingComment(octokit, owner, repo, issueNumber, body) {
  const { data } = await octokit.rest.issues.createComment({
    owner,
    repo,
    issue_number: issueNumber,
    body
  });

  return data.id;
}

async function updateComment(octokit, owner, repo, commentId, body) {
  await octokit.rest.issues.updateComment({
    owner,
    repo,
    comment_id: commentId,
    body
  });
}

/**
 * Call Claude API to analyze the issue
 */
async function analyzeIssue(issueTitle, issueBody, fileTree, extraFiles = []) {
  const systemPrompt = `
You are a senior software engineer acting as a pragmatic technical lead reviewing GitHub issues.

Your goals are to help the team:
- Quickly converge on a correct and efficient execution path
- Surface *non-obvious* decisions, tradeoffs, and coordination questions
- Ground recommendations in the actual toolchain and official documentation
- Reduce unnecessary back-and-forth by answering what can be inferred from the repo

Guidelines:
- Do NOT ask questions whose answers are trivially discoverable from common files (e.g. package.json, config files) unless there is ambiguity or a decision to be made
- Prefer questions that clarify *intent*, *scope*, or *coupled decisions* (e.g. “Should X be upgraded together with Y?”)
- If a standard or official tool, codemod, CLI, or migration guide exists, explicitly reference it
- Be concrete and opinionated when the path is well-known
- Avoid generic advice or vague best practices
- Do not hallucinate code behavior
- Base your analysis strictly on the provided repository context
- If you make assumptions, state them explicitly
- If important information is missing and cannot be inferred, ask for it

If additional file contents would materially improve the analysis:
- Add a final section titled exactly: "## 📥 Requested Files"
- List up to 5 specific file paths from the repository
- Request files only if their contents are necessary for a better answer
- Do NOT request directories or globs

When appropriate, suggest:
- Official upgrade paths, CLIs, codemods, or documented workflows
- Sequencing decisions (what should be upgraded together vs separately)
- Clear stopping points or verification steps

Always respond in markdown, using exactly the following sections and emojis:

## ❓ Curious Questions
Ask only high-signal questions a senior engineer would ask the issue author.
Focus on decisions, scope alignment, or coordinated changes — not basic facts easily derived from the repo.

## 🧠 Analysis or Plan
Propose a concrete, realistic execution plan.
Reference official tooling or documentation when applicable.
If assumptions are made, state them explicitly.

## 📂 Relevant Files
List files or directories that are likely involved.
Do not speculate about files unless clearly inferred; call out uncertainty explicitly.

## ⚠️ Risks or Notes
Call out important edge cases, upgrade risks, or ecosystem constraints.
If none apply, state that explicitly.

Response constraints:
- Use at most 5 bullet points per section
- Keep each bullet point to 1–2 short sentences
- Do not exceed ~400 words total
- Summarize aggressively and prefer actionable guidance
`;

  const userPrompt = `Analyze this GitHub issue:

**Title:** ${issueTitle}

**Body:**
${issueBody}

**Repository Structure (shallow, up to 3 levels):**
${fileTree.length > 0 ? fileTree.join('\n') : 'No files found'}

${extraFiles.length > 0 ? `
**Additional File Contents (requested):**
${extraFiles.map(f => `\n---\n### ${f.path}\n${f.content}`).join('\n')}
` : ''}
`;

  try {
    const message = await anthropic.messages.create({
      model: 'claude-sonnet-4-5-20250929',
      max_tokens: 900,
      system: systemPrompt,
      messages: [
        {
          role: 'user',
          content: userPrompt
        }
      ]
    });

    return message.content[0].text;
  } catch (error) {
    console.error('Claude API error:', error.message);
    throw error;
  }
}

/**
 * Main webhook handler
 */
app.post('/webhook', async (req, res) => {
  console.log('[Webhook] Received webhook request');
  
  // Verify webhook signature
  const signature = req.headers['x-hub-signature-256'];
  if (!verifySignature(req.body, signature)) {
    console.log('[Webhook] Invalid signature');
    return res.status(401).send('Invalid signature');
  }
  console.log('[Webhook] Signature verified');

  const { action, comment, issue, installation, repository } = req.body;
  const eventType = req.headers['x-github-event'];
  console.log(`[Webhook] Event type: ${eventType}, Action: ${action}`);

  // Only process issue_comment events
  if (eventType !== 'issue_comment') {
    console.log(`[Webhook] Ignoring event type: ${eventType}`);
    return res.status(200).send('Event ignored');
  }

  // Only process when comment is created and contains @claude-judge
  const commentBody = comment?.body || '';
  const hasCommand = commentBody.includes('@claude-judge');
  console.log(`[Webhook] Comment body preview: ${commentBody.substring(0, 100)}...`);
  console.log(`[Webhook] Contains @claude-judge: ${hasCommand}`);
  
  if (action !== 'created' || !hasCommand) {
    console.log('[Webhook] Command not found or action not created');
    return res.status(200).send('Command not found');
  }

  // Early return if no installation ID
  if (!installation?.id) {
    console.log('[Webhook] Missing installation ID');
    return res.status(400).send('Missing installation ID');
  }
  console.log(`[Webhook] Installation ID: ${installation.id}`);

  try {
    const owner = repository.owner.login;
    const repo = repository.name;
    const issueNumber = issue.number;
    console.log(`[Webhook] Processing issue #${issueNumber} in ${owner}/${repo}`);

    // Log link to files endpoint
    const protocol = req.protocol || 'http';
    const host = req.get('host') || `localhost:${PORT}`;
    const filesUrl = `${protocol}://${host}/files?owner=${encodeURIComponent(owner)}&repo=${encodeURIComponent(repo)}&installation_id=${installation.id}`;
    console.log(`[Webhook] Files endpoint URL: ${filesUrl}`);

    // Get installation access token
    console.log('[Webhook] Generating installation access token...');
    const installationToken = await getInstallationToken(installation.id);
    console.log('[Webhook] Installation token obtained');

    // Create authenticated Octokit client
    const octokit = new Octokit({
      auth: installationToken
    });

    // Fetch issue details
    console.log('[Webhook] Fetching issue details...');
    const { data: issueData } = await octokit.rest.issues.get({
      owner,
      repo,
      issue_number: issueNumber
    });
    console.log(`[Webhook] Issue title: ${issueData.title}`);

    // Get repository file tree
    console.log('[Webhook] Fetching repository file tree...');
    const fileTree = await getFileTree(octokit, owner, repo);
    console.log(`[Webhook] Found ${fileTree.length} files in repository`);

    const workingMessage = `🤖 **Issue Judge is reviewing this issue**

I'm analyzing the repository context and may fetch a small number of relevant files.
This usually takes a few seconds. I'll update this comment shortly with findings.`;

    // Create a temporary "working" comment
    console.log('[Webhook] Creating working comment...');
    const workingCommentId = await createWorkingComment(
      octokit,
      owner,
      repo,
      issueNumber,
      workingMessage
    );

    // Analyze issue with Claude
    console.log('[Webhook] Calling Claude API for analysis...');
    const analysis = await analyzeIssue(
      issueData.title,
      issueData.body || '',
      fileTree
    );

    // Check if Claude requested specific files
    const requestedMatch = analysis.match(/## 📥 Requested Files([\s\S]*)$/m);
    let finalAnalysis = analysis;

    if (requestedMatch) {
      const requestedPaths = requestedMatch[1]
        .split('\n')
        .map(l => l.replace(/^[-*]\s*/, '').trim())
        .filter(Boolean);

      if (requestedPaths.length > 0) {
        console.log('[Webhook] Claude requested files:', requestedPaths);

        const extraFiles = await readFilesBatch(
          octokit,
          owner,
          repo,
          requestedPaths,
          5,
          200_000
        );

        if (extraFiles.length > 0) {
          console.log('[Webhook] Re-running analysis with requested file contents');
          finalAnalysis = await analyzeIssue(
            issueData.title,
            issueData.body || '',
            fileTree,
            extraFiles
          );
        }
      }
    }

    console.log(`[Webhook] Analysis completed (${finalAnalysis.length} characters)`);

    // Update the working comment with the final analysis
    console.log('[Webhook] Updating working comment with final analysis...');
    await updateComment(
      octokit,
      owner,
      repo,
      workingCommentId,
      finalAnalysis
    );
    console.log('[Webhook] Comment updated successfully');

    res.status(200).send('Analysis completed');
  } catch (error) {
    console.error('[Webhook] Error processing webhook:', error);
    console.error('[Webhook] Error stack:', error.stack);
    res.status(500).send('Internal server error');
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).send('OK');
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
