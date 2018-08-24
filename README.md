# Yo, Stroopwafel!

YoStroop is a bot that allows members of a Slack workspace to give rewards to each other, usually as a way of saying "thank you" for help and valuable contributions. 
It was developed using Python, Azure Functions v2.0 and Cosmos DB.

## What it does

After you install, the bot listens to public channels in your Slack workspace. Whenever someone writes a message that contains the string `:stroopwafel:`, the bot will parse the message looking for mentions, and will record that each of the mentioned users got a stroopwafel. At the end of the month (still in development) the bot will communicate the leaderboard - who received the most stroopwafels. Note that the string `:stroopwafel:` represents an emoji as it's between `:`. Our slack workspace uses a custom emoji for `:stroopwafel:`.

## Installation

<a href="https://slack.com/oauth/authorize?scope=channels:history%20users.profile:read%20chat:write&client_id=412513733287.419967497237"><img alt="Add to Slack" height="40" width="139" src="https://platform.slack-edge.com/img/add_to_slack.png" srcset="https://platform.slack-edge.com/img/add_to_slack.png 1x, https://platform.slack-edge.com/img/add_to_slack@2x.png 2x" /></a>

## Future work

* Monthly report
* Limits on how many stroopwafels each user can send per month
* Customization of the "gift" - today it's a stroopwafel, but we can allow different workspaces to use different emojis

## Architecture and development

Please see [here](https://meyerperin.com/post/yo-stroopwafel/) for more information.
