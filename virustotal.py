import os.path
import discord
from dotenv import load_dotenv
from discord.ext.commands import Bot
import os
import requests
import hashlib
import time
bot = Bot('!')
is_mali = None
not_mali = None
scan_error = None
not_found = None
guild_id = 'test'
load_dotenv()
TOKEN = os.getenv('DISCORD_TOKEN')
GUILD = os.getenv('DISCORD_GUILD')

TOKEN = ("No Peeking")
client = discord.Client()
file_name = ''


def VT_Request(key, hash, output):
    global is_mali
    global not_mali
    global scan_error
    global not_found
    is_mali = None
    not_mali = None
    scan_error = None
    not_found = None
    params = {'apikey': key, 'resource': hash}
    url = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
    json_response = url.json()
    response = int(json_response.get('response_code'))
    if response == 0:
        print(hash + ' is not in Virus Total')
        not_found = True
        file = open(output, 'a')
        file.write(hash + ' is not in Virus Total')
        file.write('\n')
        file.close()
    elif response == 1:
        positives = int(json_response.get('positives'))
        if positives == 0:
            print(hash + ' is not malicious')
            not_mali = True
            file = open(output, 'a')
            file.write(hash + ' is not malicious')
            file.write('\n')
            file.close()
        else:
            print(hash + ' is malicious')
            is_mali = True
            file = open(output, 'a')
            file.write(hash + ' is malicious. Hit Count:' + str(positives))
            file.write('\n')
            file.close()
    else:
        print(hash + ' could not be searched. Please try again later.')
        scan_error = True




def hash_file(filename):

    h = hashlib.sha1()

    with open(filename, 'rb') as file:

        chunk = 0
        while chunk != b'':

            chunk = file.read(1024)
            h.update(chunk)


    return h.hexdigest()

@bot.command()

async def helpme(ctx):
    activity = discord.Game(name="!helpme")
    embed = discord.Embed(title="Commands", description="!helpme                ", color=0x33d17a)
    embed.set_author(name="Help Menu")
    embed.add_field(name="VirusTotal Commands", value="!verify", inline=True)
    embed.add_field(name="VirusTotal Help", value="!verifyhelp", inline=False)
    await ctx.send(embed=embed)

@bot.command()
async def verifyhelp(ctx):
    activity = discord.Game(name="!helpme")
    embed = discord.Embed(title="!verify Help", description="!verify Scans A File With Virus Total When It Is Uploaded With One        If the File Is To Big You Can Compress It Into Zip Or Similar Format         ", color=0x33d17a)
    embed.set_author(name="Help Menu")
    await ctx.send(embed=embed)




@bot.command()
async def verify(ctx):
    activity = discord.Game(name="!helpme")
    try:
        attachment = ctx.message.attachments[0]

        attchfile = (attachment.url)
        file_name = attachment.filename
        print(attachment.url)
    except Exception:
        await ctx.send('Either Bad File Type Or No File')
        return
    os.chdir('/bot')
    os.system(f'wget {attchfile}')
    hash_for_vt = hash_file(f'/bot/{file_name}')



    hash_for_vt = hash_file(f'/bot/{file_name}')
    os.system(f'curl --request POST \
--url https://www.virustotal.com/api/v3/files \
--header \'x-apikey: VIRUSTOTAL API KEY\' \
--form file=@/bot/{file_name}')

    list_of_files = os.listdir()
    file_name = list_of_files[0]


    os.system(f'sudo rm -rf {file_name}')
    VT_Request('VIRUSTOTAL API KEY', hash_for_vt, 'a')
    if not_mali == True:
        await ctx.reply('VirusTotal Did ** Not ** Deem This File Malicious| If You Have Info To Suggest Otherwise Please Contact A Moderator')
    if is_mali == True:
        await ctx.reply('This Has Been Deemed Malicious| You Have Been Muted | Please Message A Moderator To Appeal This Mute')
        await ctx.message.delete()
        await ctx.send({ctx.message.author})
        time.sleep(4)

    if not_found == True:
        await ctx.reply('File Not Found On VirusTotal Please Make Sure You Have Uploaded This On VirusTotal.com Prior To Running This Command')
        await ctx.message.delete()



    md5 = hashlib.md5()
    api = 'VIRUSTOTAL API KEY'



bot.run(TOKEN)