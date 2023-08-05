const fs = require('fs');
const Discord = require('discord.js');
const axios = require('axios');
const crypto = require('crypto');
require('dotenv').config();

const client = new Discord.Client({ intents: ['GUILDS', 'GUILD_MESSAGES'] });

client.once('ready', () => {
  console.log('Bot is online yer fag');
});

function VT_Request(apiKey, hash, output, message) {
  const params = { apikey: apiKey, resource: hash };
  const url = `https://www.virustotal.com/vtapi/v2/file/report`;

  axios
    .get(url, { params })
    .then((response) => {
      const data = response.data;
      const responseCode = data.response_code;

      if (responseCode === 0) {
        console.log(`${hash} is not in VirusTotal`);
        message.channel.send(`${hash} is not in VirusTotal`);
      } else if (responseCode === 1) {
        const positives = data.positives;
        if (positives === 0) {
          console.log(`${hash} is not malicious`);
          message.channel.send(`${hash} is not malicious`);
        } else {
          console.log(`${hash} is malicious`);
          message.channel.send(`${hash} is malicious`);
          message.member.roles.add('ROLE_ID'); // Replace with the actual role ID for muting users
          setTimeout(() => {
            message.member.roles.remove('ROLE_ID');
          }, 15 * 60 * 1000);
        }
      } else {
        console.log(`${hash} could not be searched. Please try again later.`);
        message.channel.send(`${hash} could not be searched. Please try again later.`);
      }
    })
    .catch((error) => {
      console.error(error.message);
      message.channel.send(`An error occurred while scanning the file. Please try again later.`);
    })
    .finally(() => {
      fs.unlinkSync(output); // Delete the file from the PC
    });
}

function hashFile(filename) {
  const hash = crypto.createHash('sha1');
  const fileData = fs.readFileSync(filename);

  hash.update(fileData);
  return hash.digest('hex');
}

client.on('messageCreate', async (message) => {
  if (!message.author.bot && message.attachments.size > 0) {
    try {
      message.attachments.each(async (attachment) => {
        const fileURL = attachment.url;
        const fileName = attachment.name;
        const apiKey = process.env.VIRUSTOTAL_API_KEY;

        const writer = fs.createWriteStream(`./${fileName}`);
        const response = await axios.get(fileURL, { responseType: 'stream' });
        response.data.pipe(writer);

        writer.on('finish', () => {
          const hashForVT = hashFile(`./${fileName}`);
          VT_Request(apiKey, hashForVT, `./${fileName}`, message);
        });
      });
    } catch (error) {
      console.error(error.message);
      message.channel.send('An error occurred (please report this to toney)');
    }
  }
});

client.login(process.env.DISCORD_TOKEN);
