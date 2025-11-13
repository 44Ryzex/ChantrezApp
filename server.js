const { Client, GatewayIntentBits, Partials, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle, ChannelType, PermissionFlagsBits } = require('discord.js');
const express = require('express');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const http = require('http');
const socketIO = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = socketIO(server);

const PORTS = [3000, 3001, 3002, 3003, 3004, 3005];
let PORT = process.env.PORT || 3000;

const userBots = new Map();

const usersPath = path.join(__dirname, 'data', 'users.json');
const keysPath = path.join(__dirname, 'data', 'keys.json');

if (!fs.existsSync(path.join(__dirname, 'data'))) fs.mkdirSync(path.join(__dirname, 'data'));

let users = [];
let keys = [];

if (fs.existsSync(usersPath)) {
    users = JSON.parse(fs.readFileSync(usersPath, 'utf8'));
    users = users.map(u => ({
        ...u,
        botToken: u.botToken || '',
        guildId: u.guildId || '',
        botStatus: u.botStatus || { online: false, ready: false },
        ticketSettings: u.ticketSettings || {
            embedTitle: 'Support Ticket',
            embedDescription: 'Open a ticket for support',
            staffRole: '',
            ticketsCategory: '',
            closedCategory: '',
            ticketChannel: ''
        },
        activityTestMessages: u.activityTestMessages || {
            title: '⚡ Activity Test',
            description: 'Join!',
            timeFieldName: '⏰ Time',
            noteFieldName: '📝 Note',
            noteFieldValue: 'Don\'t forget!'
        },
        ingameAncMessages: u.ingameAncMessages || {
            title: '🎮 Ingame'
        },
        guardSettings: u.guardSettings || {
            radar: {
                roles: []
            },
            channelProtection: {
                createLimit: 3,
                deleteLimit: 2,
                resetTime: 3600000,
                action: 'kick',
                assignRole: '',
                deleteAction: '',
                deleteAssignRole: ''
            },
            memberProtection: {
                banLimit: 2,
                kickLimit: 5,
                timeoutLimit: 10,
                resetTime: 3600000,
                action: 'kick',
                assignRole: ''
            },
            roleProtection: {
                createLimit: 3,
                deleteLimit: 2,
                resetTime: 3600000,
                action: 'kick',
                assignRole: ''
            },
            logChannel: ''
        },
        guardLogs: u.guardLogs || []
    }));
    // Reset all bot statuses on server startup (they're not actually connected)
    users.forEach(user => {
        if (user.botStatus && (user.botStatus.online || user.botStatus.ready)) {
            user.botStatus.online = false;
            user.botStatus.ready = false;
        }
    });
    
    saveUsers();
    console.log('🔄 Bot statuses reset - All users must restart their bots');
}
if (fs.existsSync(keysPath)) keys = JSON.parse(fs.readFileSync(keysPath, 'utf8'));

function saveUsers() { fs.writeFileSync(usersPath, JSON.stringify(users, null, 4)); }
function saveKeys() { fs.writeFileSync(keysPath, JSON.stringify(keys, null, 4)); }

if (users.length === 0) {
    users.push({ 
        id: uuidv4(), 
        username: 'admin', 
        password: bcrypt.hashSync('admin', 10), 
        email: 'admin@panel.com', 
        discordId: '000000000000000000', 
        accountType: 'admin', 
        registeredIP: '0.0.0.0', 
        allowedIP: '0.0.0.0', 
        banned: false, 
        createdAt: new Date().toISOString(),
        botToken: '',
        guildId: '',
        botStatus: { online: false, ready: false },
        ticketSettings: {
            embedTitle: 'Support Ticket',
            embedDescription: 'Open a ticket for support',
            staffRole: '',
            ticketsCategory: '',
            closedCategory: '',
            ticketChannel: ''
        },
        activityTestMessages: {
            title: '⚡ Activity Test',
            description: 'Join!',
            timeFieldName: '⏰ Time',
            noteFieldName: '📝 Note',
            noteFieldValue: 'Don\'t forget!'
        },
        ingameAncMessages: {
            title: '🎮 Ingame'
        },
        guardLogs: []
    });
    saveUsers();
    console.log('✅ Default admin: admin/admin');
}

let logs = [];
function addLog(type, msg) { logs.push({ type, message: msg, timestamp: new Date().toISOString() }); if (logs.length > 100) logs.shift(); console.log(`[${type}] ${msg}`); }

const userActiveTickets = new Map();
const userTicketClaims = new Map();
const userIngameAnnouncements = new Map();
const userActivityTests = new Map();
const userTicketCounters = new Map();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Configure session with file store for persistence
const fileStoreOptions = {
    path: path.join(__dirname, 'data', 'sessions'),
    retries: 2,
    ttl: 24 * 60 * 60 // 24 hours in seconds
};

app.use(session({ 
    store: new FileStore(fileStoreOptions),
    secret: 'secret-' + uuidv4(), 
    resave: false, 
    saveUninitialized: false, 
    cookie: { secure: false, maxAge: 24*60*60*1000 } 
}));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

function getClientIP(req) { return req.headers['x-forwarded-for']?.split(',')[0] || req.connection.remoteAddress || '0.0.0.0'; }

function requireAuth(req, res, next) {
    if (!req.session.userId) return res.redirect('/login');
    const user = users.find(u => u.id === req.session.userId);
    if (!user) { req.session.destroy(); return res.redirect('/login'); }
    if (user.banned) { req.session.destroy(); return res.redirect('/banned'); }
    const clientIP = getClientIP(req);
    if (user.allowedIP !== '0.0.0.0' && user.allowedIP !== clientIP) return res.redirect('/ip-blocked');
    req.user = user;
    next();
}

function requireAdmin(req, res, next) {
    if (!req.user || req.user.accountType !== 'admin') return res.status(403).send('Access denied');
    next();
}

io.on('connection', (socket) => {
    socket.on('checkBan', (userId) => {
        const user = users.find(u => u.id === userId);
        if (user && user.banned) socket.emit('banned');
    });
});

function createUserBot(userId) {
    const user = users.find(u => u.id === userId);
    if (!user || !user.botToken) return null;

    const client = new Client({
        intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages, GatewayIntentBits.GuildMembers, GatewayIntentBits.GuildMessageReactions, GatewayIntentBits.DirectMessages, GatewayIntentBits.MessageContent],
        partials: [Partials.Message, Partials.Channel, Partials.Reaction]
    });

    if (!userActiveTickets.has(userId)) userActiveTickets.set(userId, new Map());
    if (!userTicketClaims.has(userId)) userTicketClaims.set(userId, new Map());
    if (!userIngameAnnouncements.has(userId)) userIngameAnnouncements.set(userId, new Map());
    if (!userActivityTests.has(userId)) userActivityTests.set(userId, new Map());
    if (!userTicketCounters.has(userId)) userTicketCounters.set(userId, 1);

    client.once('ready', () => {
        user.botStatus.ready = true;
        user.botStatus.online = true;
        saveUsers();
        addLog('success', `Bot ready for ${user.username}: ${client.user.tag}`);
    });

    client.on('error', (err) => {
        addLog('error', `Bot error for ${user.username}: ${err.message}`);
    });

    client.on('messageReactionAdd', async (reaction, reactUser) => {
        if (reactUser.bot) return;
        if (reaction.partial) try { await reaction.fetch(); } catch(e) { return; }
        
        const ingameMap = userIngameAnnouncements.get(userId) || new Map();
        for (const [mid, data] of ingameMap.entries()) {
            if (reaction.message.id === mid && !data.locked) {
                const count = reaction.count - 1;
                if (count >= data.limit) {
                    data.locked = true;
                    const users = await reaction.users.fetch();
                    const userList = Array.from(users.values()).filter(u => !u.bot).slice(0, data.limit);
                    const mentions = userList.map((u, i) => `${i + 1}- <@${u.id}>`).join('\n');
                    
                    await reaction.message.reply(`\n\n${mentions}`);
                    addLog('success', `Ingame done for ${user.username}: ${data.limit}`);
                    ingameMap.delete(mid);
                }
            }
        }
        
        const activityMap = userActivityTests.get(userId) || new Map();
        for (const [mid, data] of activityMap.entries()) {
            if (reaction.message.id === mid) data.participants.add(reactUser.id);
        }
    });

    // Guard system maps for tracking limits
    const userGuardLimits = new Map();
    if (!userGuardLimits.has(userId)) {
        userGuardLimits.set(userId, {
            channelActions: new Map(),
            memberActions: new Map(), 
            roleActions: new Map()
        });
    }

    // Helper function to send guard log
    async function sendGuardLog(message, color = '#ff0000') {
        try {
            const logChannelId = user.guardSettings?.logChannel;
            if (!logChannelId) return;
            
            const guild = client.guilds.cache.get(user.guildId);
            if (!guild) return;
            
            const logChannel = guild.channels.cache.get(logChannelId);
            if (!logChannel) return;

            const embed = new EmbedBuilder()
                .setColor(color)
                .setTitle('🛡️ Guard System')
                .setDescription(message)
                .setTimestamp();
                
            await logChannel.send({ embeds: [embed] });
        } catch (error) {
            console.error('Guard log error:', error);
        }
    }

    // Helper function to punish user
    async function punishUser(guild, targetId, action, reason, assignRole = null) {
        try {
            const member = await guild.members.fetch(targetId).catch(() => null);
            if (!member) return false;

            if (action === 'kick') {
                await member.kick(reason);
                await sendGuardLog(`🦶 **Kick:** <@${targetId}>\n**Reason:** ${reason}`, '#ff0000');
                addLog('warning', `Guard kicked ${member.user.tag} for ${user.username}: ${reason}`);
                addGuardLog(userId, 'warning', `🦶 Kicked ${member.user.tag}: ${reason}`);
            } else if (action === 'ban') {
                await member.ban({ reason, deleteMessageDays: 1 });
                await sendGuardLog(`🔨 **Ban:** <@${targetId}>\n**Reason:** ${reason}`, '#ff0000');
                addLog('warning', `Guard banned ${member.user.tag} for ${user.username}: ${reason}`);
                addGuardLog(userId, 'error', `🔨 Banned ${member.user.tag}: ${reason}`);
            } else if (action === 'removeRoles') {
                // Remove all roles except @everyone
                const rolesToRemove = member.roles.cache.filter(role => role.id !== guild.id);
                if (rolesToRemove.size > 0) {
                    await member.roles.set([]);
                }
                
                // Add assigned role if specified
                if (assignRole) {
                    try {
                        await member.roles.add(assignRole);
                    } catch (err) {
                        console.error('Error adding assign role:', err);
                    }
                }
                
                await sendGuardLog(`🚫 **Remove Roles:** <@${targetId}>\n**Reason:** ${reason}${assignRole ? `\n**Assigned Role:** <@&${assignRole}>` : ''}`, '#ff0000');
                addLog('warning', `Guard removed roles from ${member.user.tag} for ${user.username}: ${reason}`);
                addGuardLog(userId, 'warning', `🚫 Removed roles from ${member.user.tag}: ${reason}`);
            }
            return true;
        } catch (error) {
            console.error('Punishment error:', error);
            return false;
        }
    }

    // Guard event listeners
    client.on('channelCreate', async (channel) => {
        if (!user.guardSettings?.channelProtection?.enabled) return;
        const { createLimit, resetTime, action, deleteAction } = user.guardSettings.channelProtection;
        
        const auditLogs = await channel.guild.fetchAuditLogs({ type: 10, limit: 1 }).catch(() => null);
        if (!auditLogs || !auditLogs.entries.first()) return;
        
        const executor = auditLogs.entries.first().executor;
        if (!executor || executor.bot) return;
        
        const limits = userGuardLimits.get(userId);
        const now = Date.now();
        const userActions = limits.channelActions.get(executor.id) || { creates: [], deletes: [] };
        
        userActions.creates = userActions.creates.filter(time => now - time < resetTime);
        userActions.creates.push(now);
        limits.channelActions.set(executor.id, userActions);
        
        if (userActions.creates.length >= createLimit) {
            const assignRole = action === 'removeRoles' ? user.guardSettings.channelProtection.assignRole : null;
            await punishUser(channel.guild, executor.id, action, `Channel creation limit exceeded (${createLimit})`, assignRole);
            userActions.creates = [];
        }
    });

    client.on('channelDelete', async (channel) => {
        if (!user.guardSettings?.channelProtection?.enabled) return;
        const { deleteLimit, resetTime, action } = user.guardSettings.channelProtection;
        
        const auditLogs = await channel.guild.fetchAuditLogs({ type: 12, limit: 1 }).catch(() => null);
        if (!auditLogs || !auditLogs.entries.first()) return;
        
        const executor = auditLogs.entries.first().executor;
        if (!executor || executor.bot) return;
        
        const limits = userGuardLimits.get(userId);
        const now = Date.now();
        const userActions = limits.channelActions.get(executor.id) || { creates: [], deletes: [] };
        
        userActions.deletes = userActions.deletes.filter(time => now - time < resetTime);
        userActions.deletes.push(now);
        limits.channelActions.set(executor.id, userActions);
        
        if (userActions.deletes.length >= deleteLimit) {
            const assignRole = action === 'removeRoles' ? user.guardSettings.channelProtection.assignRole : null;
            await punishUser(channel.guild, executor.id, action, `Channel deletion limit exceeded (${deleteLimit})`, assignRole);
            userActions.deletes = [];
        }
    });

    client.on('guildBanAdd', async (ban) => {
        if (!user.guardSettings?.memberProtection?.enabled) return;
        const { banLimit, resetTime, action } = user.guardSettings.memberProtection;
        
        const auditLogs = await ban.guild.fetchAuditLogs({ type: 22, limit: 1 }).catch(() => null);
        if (!auditLogs || !auditLogs.entries.first()) return;
        
        const executor = auditLogs.entries.first().executor;
        if (!executor || executor.bot) return;
        
        // Check if executor is in radar list
        const radarRoles = user.guardSettings?.radar?.roles || [];
        const member = await ban.guild.members.fetch(executor.id).catch(() => null);
        if (member && radarRoles.some(role => member.roles.cache.has(role.id))) {
            const radarAction = user.guardSettings.radar.action;
            await punishUser(ban.guild, executor.id, radarAction, 'Radar role - Ban action');
            return;
        }
        
        const limits = userGuardLimits.get(userId);
        const now = Date.now();
        const userActions = limits.memberActions.get(executor.id) || { bans: [], kicks: [], timeouts: [] };
        
        userActions.bans = userActions.bans.filter(time => now - time < resetTime);
        userActions.bans.push(now);
        limits.memberActions.set(executor.id, userActions);
        
        if (userActions.bans.length >= banLimit) {
            const assignRole = action === 'removeRoles' ? user.guardSettings.memberProtection.assignRole : null;
            await punishUser(ban.guild, executor.id, action, `Ban limit exceeded (${banLimit})`, assignRole);
            userActions.bans = [];
        }
    });

    client.on('guildMemberRemove', async (member) => {
        if (!user.guardSettings?.memberProtection?.enabled) return;
        const { kickLimit, resetTime, action } = user.guardSettings.memberProtection;
        
        // Wait a bit for audit log to be created
        setTimeout(async () => {
            const auditLogs = await member.guild.fetchAuditLogs({ type: 20, limit: 1 }).catch(() => null);
            if (!auditLogs || !auditLogs.entries.first()) return;
            
            const auditEntry = auditLogs.entries.first();
            if (!auditEntry || auditEntry.target.id !== member.id) return;
            
            const executor = auditEntry.executor;
            if (!executor || executor.bot) return;
            
            // Check if executor is in radar list
            const radarRoles = user.guardSettings?.radar?.roles || [];
            const executorMember = await member.guild.members.fetch(executor.id).catch(() => null);
            if (executorMember && radarRoles.some(role => executorMember.roles.cache.has(role.id))) {
                const radarAction = user.guardSettings.radar.action;
                await punishUser(member.guild, executor.id, radarAction, 'Radar role - Kick action');
                return;
            }
            
            const limits = userGuardLimits.get(userId);
            const now = Date.now();
            const userActions = limits.memberActions.get(executor.id) || { bans: [], kicks: [], timeouts: [] };
            
            userActions.kicks = userActions.kicks.filter(time => now - time < resetTime);
            userActions.kicks.push(now);
            limits.memberActions.set(executor.id, userActions);
            
            if (userActions.kicks.length >= kickLimit) {
                const assignRole = action === 'removeRoles' ? user.guardSettings.memberProtection.assignRole : null;
                await punishUser(member.guild, executor.id, action, `Kick limit exceeded (${kickLimit})`, assignRole);
                userActions.kicks = [];
            }
        }, 2000);
    });

    client.on('guildMemberUpdate', async (oldMember, newMember) => {
        if (!user.guardSettings?.memberProtection?.enabled) return;
        const { timeoutLimit, resetTime, action } = user.guardSettings.memberProtection;
        
        // Check if member was timed out
        if (!oldMember.communicationDisabledUntil && newMember.communicationDisabledUntil) {
            const auditLogs = await newMember.guild.fetchAuditLogs({ type: 24, limit: 1 }).catch(() => null);
            if (!auditLogs || !auditLogs.entries.first()) return;
            
            const executor = auditLogs.entries.first().executor;
            if (!executor || executor.bot) return;
            
            // Check if executor is in radar list
            const radarRoles = user.guardSettings?.radar?.roles || [];
            const executorMember = await newMember.guild.members.fetch(executor.id).catch(() => null);
            if (executorMember && radarRoles.some(role => executorMember.roles.cache.has(role.id))) {
                const radarAction = user.guardSettings.radar.action;
                await punishUser(newMember.guild, executor.id, radarAction, 'Radar role - Timeout action');
                return;
            }
            
            const limits = userGuardLimits.get(userId);
            const now = Date.now();
            const userActions = limits.memberActions.get(executor.id) || { bans: [], kicks: [], timeouts: [] };
            
            userActions.timeouts = userActions.timeouts.filter(time => now - time < resetTime);
            userActions.timeouts.push(now);
            limits.memberActions.set(executor.id, userActions);
            
            if (userActions.timeouts.length >= timeoutLimit) {
                const assignRole = action === 'removeRoles' ? user.guardSettings.memberProtection.assignRole : null;
                await punishUser(newMember.guild, executor.id, action, `Timeout limit exceeded (${timeoutLimit})`, assignRole);
                userActions.timeouts = [];
            }
        }
    });

    client.on('roleCreate', async (role) => {
        if (!user.guardSettings?.roleProtection?.enabled) return;
        const { createLimit, resetTime, action } = user.guardSettings.roleProtection;
        
        const auditLogs = await role.guild.fetchAuditLogs({ type: 30, limit: 1 }).catch(() => null);
        if (!auditLogs || !auditLogs.entries.first()) return;
        
        const executor = auditLogs.entries.first().executor;
        if (!executor || executor.bot) return;
        
        const limits = userGuardLimits.get(userId);
        const now = Date.now();
        const userActions = limits.roleActions.get(executor.id) || { creates: [], deletes: [] };
        
        userActions.creates = userActions.creates.filter(time => now - time < resetTime);
        userActions.creates.push(now);
        limits.roleActions.set(executor.id, userActions);
        
        if (userActions.creates.length >= createLimit) {
            const assignRole = action === 'removeRoles' ? user.guardSettings.roleProtection.assignRole : null;
            await punishUser(role.guild, executor.id, action, `Role creation limit exceeded (${createLimit})`, assignRole);
            userActions.creates = [];
        }
    });

    client.on('roleDelete', async (role) => {
        if (!user.guardSettings?.roleProtection?.enabled) return;
        const { deleteLimit, resetTime, action } = user.guardSettings.roleProtection;
        
        const auditLogs = await role.guild.fetchAuditLogs({ type: 32, limit: 1 }).catch(() => null);
        if (!auditLogs || !auditLogs.entries.first()) return;
        
        const executor = auditLogs.entries.first().executor;
        if (!executor || executor.bot) return;
        
        const limits = userGuardLimits.get(userId);
        const now = Date.now();
        const userActions = limits.roleActions.get(executor.id) || { creates: [], deletes: [] };
        
        userActions.deletes = userActions.deletes.filter(time => now - time < resetTime);
        userActions.deletes.push(now);
        limits.roleActions.set(executor.id, userActions);
        
        if (userActions.deletes.length >= deleteLimit) {
            const assignRole = action === 'removeRoles' ? user.guardSettings.roleProtection.assignRole : null;
            await punishUser(role.guild, executor.id, action, `Role deletion limit exceeded (${deleteLimit})`, assignRole);
            userActions.deletes = [];
        }
    });

    client.on('interactionCreate', async (interaction) => {
        if (!interaction.isButton()) return;
        const guild = interaction.guild;
        
        const activeTickets = userActiveTickets.get(userId) || new Map();
        const ticketClaims = userTicketClaims.get(userId) || new Map();
        let ticketCounter = userTicketCounters.get(userId) || 1;

        if (interaction.customId === 'create_ticket') {
            if (activeTickets.has(interaction.user.id)) return interaction.reply({ content: '❌ You already have a ticket!', ephemeral: true });
            const userName = interaction.user.username.toLowerCase().replace(/[^a-z0-9]/g, '');
            const ticketChannel = await guild.channels.create({ 
                name: `ticket-${userName}-${ticketCounter}`, 
                type: ChannelType.GuildText, 
                parent: user.ticketSettings?.ticketsCategory || null, 
                permissionOverwrites: [
                    { id: guild.id, deny: [PermissionFlagsBits.ViewChannel] }, 
                    { id: interaction.user.id, allow: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages] }, 
                    { id: user.ticketSettings?.staffRole || guild.id, allow: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages] }
                ] 
            });
            ticketCounter++;
            userTicketCounters.set(userId, ticketCounter);
            activeTickets.set(interaction.user.id, ticketChannel.id);
            
            const ticketEmbed = new EmbedBuilder()
                .setColor('#000000')
                .setTitle(user.ticketSettings?.embedTitle || 'Support Ticket')
                .setDescription(user.ticketSettings?.embedDescription || 'Open a ticket for support')
                .setTimestamp();
            
            const ticketButtons = new ActionRowBuilder().addComponents(
                new ButtonBuilder().setCustomId('claim_ticket').setLabel('Claim').setEmoji('✋').setStyle(ButtonStyle.Primary), 
                new ButtonBuilder().setCustomId('close_ticket').setLabel('Close').setEmoji('🔒').setStyle(ButtonStyle.Danger)
            );
            
            const ticketMessage = await ticketChannel.send({ 
                content: `<@${interaction.user.id}> ${user.ticketSettings?.staffRole ? `<@&${user.ticketSettings.staffRole}>` : ''}`, 
                embeds: [ticketEmbed], 
                components: [ticketButtons] 
            });
            
            ticketClaims.set(ticketChannel.id, { messageId: ticketMessage.id, claimed: false, claimedBy: null });
            await interaction.reply({ content: `✅ Ticket created: ${ticketChannel}`, ephemeral: true });
            addLog('info', `Ticket for ${user.username}: ${userName}-${ticketCounter-1}`);
        }
        
        if (interaction.customId === 'claim_ticket') {
            if (user.ticketSettings?.staffRole && !interaction.member.roles.cache.has(user.ticketSettings.staffRole)) {
                return interaction.reply({ content: '❌ No permission!', ephemeral: true });
            }
            const cid = interaction.channel.id;
            const claimData = ticketClaims.get(cid);
            if (!claimData || claimData.claimed) return interaction.reply({ content: '❌ Already claimed!', ephemeral: true });
            claimData.claimed = true;
            claimData.claimedBy = interaction.user.id;
            ticketClaims.set(cid, claimData);
            try {
                const message = await interaction.channel.messages.fetch(claimData.messageId);
                const updatedEmbed = EmbedBuilder.from(message.embeds[0]).addFields({ name: '👤 Claimed By', value: `<@${interaction.user.id}>`, inline: false });
                await message.edit({ embeds: [updatedEmbed] });
            } catch (error) {
                console.error('Message update error:', error);
            }
            await interaction.reply({ content: `✅ Ticket claimed by <@${interaction.user.id}>!` });
            addLog('info', `Ticket claimed by ${interaction.user.tag} for ${user.username}`);
        }
        
        if (interaction.customId === 'close_ticket') {
            if (user.ticketSettings?.staffRole && !interaction.member.roles.cache.has(user.ticketSettings.staffRole)) {
                return interaction.reply({ content: '❌ No permission!', ephemeral: true });
            }
            await interaction.reply('🔒 Closing ticket...');
            for (const [memberId, channelId] of activeTickets.entries()) {
                if (channelId === interaction.channel.id) {
                    activeTickets.delete(memberId);
                    break;
                }
            }
            ticketClaims.delete(interaction.channel.id);
            setTimeout(async () => {
                if (user.ticketSettings?.closedCategory) {
                    await interaction.channel.setParent(user.ticketSettings.closedCategory);
                    await interaction.channel.permissionOverwrites.edit(guild.id, { ViewChannel: false, SendMessages: false });
                } else {
                    await interaction.channel.delete();
                }
                addLog('info', `Ticket closed for ${user.username}: ${interaction.channel.name}`);
            }, 3000);
        }

        if (interaction.customId.startsWith('give_role_')) {
            const roleId = interaction.customId.replace('give_role_', '');
            try {
                const member = interaction.member;
                if (member.roles.cache.has(roleId)) {
                    await member.roles.remove(roleId);
                    await interaction.reply({ content: '✅ Role removed!', ephemeral: true });
                } else {
                    await member.roles.add(roleId);
                    await interaction.reply({ content: '✅ Role given!', ephemeral: true });
                }
            } catch (error) {
                await interaction.reply({ content: '❌ Could not give role!', ephemeral: true });
            }
        }
    });

    return client;
}

app.get('/', (req, res) => res.redirect('/login'));
app.get('/login', (req, res) => res.render('login'));
app.get('/register', (req, res) => res.render('register'));

app.post('/api/auth/register', (req, res) => {
    const { username, password, email, discordId, key } = req.body;
    const clientIP = getClientIP(req);
    if (users.find(u => u.username === username)) return res.json({ success: false, message: 'Username taken!' });
    
    let accountType = 'free';
    
    if (key && key.trim() !== '') {
        const keyData = keys.find(k => k.key === key && !k.used);
        if (!keyData) return res.json({ success: false, message: 'Invalid key!' });
        keyData.used = true;
        saveKeys();
        accountType = keyData.type;
    }
    
    users.push({ 
        id: uuidv4(), 
        username, 
        password: bcrypt.hashSync(password, 10), 
        email, 
        discordId, 
        accountType, 
        registeredIP: clientIP, 
        allowedIP: clientIP, 
        banned: false, 
        createdAt: new Date().toISOString(),
        botToken: '',
        guildId: '',
        botStatus: { online: false, ready: false },
        ticketSettings: {
            embedTitle: 'Support Ticket',
            embedDescription: 'Open a ticket for support',
            staffRole: '',
            ticketsCategory: '',
            closedCategory: '',
            ticketChannel: ''
        },
        activityTestMessages: {
            title: '⚡ Activity Test',
            description: 'Join!',
            timeFieldName: '⏰ Time',
            noteFieldName: '📝 Note',
            noteFieldValue: 'Don\'t forget!'
        },
        ingameAncMessages: {
            title: '🎮 Ingame'
        }
    });
    saveUsers();
    addLog('success', `Register: ${username} (${accountType})`);
    res.json({ success: true, message: 'Registration successful!' });
});

app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    const clientIP = getClientIP(req);
    const user = users.find(u => u.username === username);
    if (!user) return res.json({ success: false, message: 'Invalid credentials!' });
    if (!bcrypt.compareSync(password, user.password)) return res.json({ success: false, message: 'Invalid credentials!' });
    if (user.banned) return res.json({ success: false, message: 'Banned!' });
    if (user.allowedIP !== '0.0.0.0' && user.allowedIP !== clientIP) return res.json({ success: false, message: 'HWID blocked!' });
    req.session.userId = user.id;
    addLog('info', `Login: ${username}`);
    res.json({ success: true, message: 'Login successful!' });
});

app.get('/logout', (req, res) => { req.session.destroy(); res.redirect('/login'); });
app.get('/banned', (req, res) => res.render('banned'));
app.get('/ip-blocked', (req, res) => res.render('ip-blocked'));
app.get('/dashboard', requireAuth, (req, res) => res.render('dashboard', { user: req.user, logs: logs.slice(-20).reverse(), page: 'dashboard' }));
app.get('/upgrade', requireAuth, (req, res) => res.render('dashboard', { user: req.user, logs, page: 'upgrade' }));
app.get('/bot-setup', requireAuth, (req, res) => req.user.accountType === 'free' ? res.render('forbidden') : res.render('dashboard', { user: req.user, logs, page: 'bot-setup' }));
app.get('/ingame-anc', requireAuth, (req, res) => req.user.accountType === 'free' ? res.render('forbidden') : res.render('dashboard', { user: req.user, logs, page: 'ingame-anc' }));
app.get('/activity-test', requireAuth, (req, res) => req.user.accountType === 'free' ? res.render('forbidden') : res.render('dashboard', { user: req.user, logs, page: 'activity-test' }));
app.get('/ticket', requireAuth, (req, res) => req.user.accountType === 'free' ? res.render('forbidden') : res.render('dashboard', { user: req.user, logs, page: 'ticket' }));
app.get('/dmanc', requireAuth, (req, res) => req.user.accountType === 'free' ? res.render('forbidden') : res.render('dashboard', { user: req.user, logs, page: 'dmanc' }));
app.get('/give-role', requireAuth, (req, res) => req.user.accountType === 'free' ? res.render('forbidden') : res.render('dashboard', { user: req.user, logs, page: 'give-role' }));
app.get('/logs', requireAuth, requireAdmin, (req, res) => res.render('dashboard', { user: req.user, logs: logs.slice(-50).reverse(), page: 'logs' }));
app.get('/admin/users', requireAuth, requireAdmin, (req, res) => res.render('dashboard', { user: req.user, logs, page: 'admin-users', allUsers: users }));
app.get('/admin/keys', requireAuth, requireAdmin, (req, res) => res.render('dashboard', { user: req.user, logs, page: 'admin-keys', allKeys: keys }));

// Guard routes
app.get('/radar-list', requireAuth, (req, res) => req.user.accountType === 'free' ? res.render('forbidden') : res.render('dashboard', { user: req.user, logs, page: 'radar-list' }));
app.get('/channel-protection', requireAuth, (req, res) => req.user.accountType === 'free' ? res.render('forbidden') : res.render('dashboard', { user: req.user, logs, page: 'channel-protection' }));
app.get('/member-protection', requireAuth, (req, res) => req.user.accountType === 'free' ? res.render('forbidden') : res.render('dashboard', { user: req.user, logs, page: 'member-protection' }));
app.get('/role-protection', requireAuth, (req, res) => req.user.accountType === 'free' ? res.render('forbidden') : res.render('dashboard', { user: req.user, logs, page: 'role-protection' }));
app.get('/guard-log', requireAuth, (req, res) => req.user.accountType === 'free' ? res.render('forbidden') : res.render('dashboard', { user: req.user, logs, page: 'guard-log' }));

app.post('/api/bot/control', requireAuth, async (req, res) => {
    if (req.user.accountType === 'free') return res.json({ success: false, message: 'Free account!' });
    const { action } = req.body;
    const user = users.find(u => u.id === req.user.id);
    
    try {
        if (action === 'start') {
            if (!user.botToken || !user.guildId) return res.json({ success: false, message: 'Missing Token/Guild ID!' });
            if (user.botStatus.online) return res.json({ success: false, message: 'Already running!' });
            
            const client = createUserBot(user.id);
            if (!client) return res.json({ success: false, message: 'Failed to create bot!' });
            
            await client.login(user.botToken);
            userBots.set(user.id, client);
            user.botStatus.online = true;
            saveUsers();
            
            addLog('success', `Bot started for ${user.username}`);
            res.json({ success: true, message: 'Bot started!' });
        } else if (action === 'stop') {
            if (!user.botStatus.online) return res.json({ success: false, message: 'Already offline!' });
            
            const client = userBots.get(user.id);
            if (client) {
                client.destroy();
                userBots.delete(user.id);
            }
            
            user.botStatus.online = false;
            user.botStatus.ready = false;
            saveUsers();
            
            addLog('info', `Bot stopped for ${user.username}`);
            res.json({ success: true, message: 'Bot stopped!' });
        }
    } catch (err) {
        addLog('error', `Bot control error for ${user.username}: ${err.message}`);
        user.botStatus.online = false;
        user.botStatus.ready = false;
        saveUsers();
        res.json({ success: false, message: err.message });
    }
});

app.post('/api/config/save', requireAuth, (req, res) => {
    if (req.user.accountType === 'free') return res.json({ success: false, message: 'Free account!' });
    const { token, guildId } = req.body;
    const user = users.find(u => u.id === req.user.id);
    
    user.botToken = token;
    user.guildId = guildId;
    saveUsers();
    
    addLog('success', `Config saved for ${user.username}`);
    res.json({ success: true, message: 'Saved!' });
});

app.get('/api/channels', requireAuth, async (req, res) => {
    try {
        const user = users.find(u => u.id === req.user.id);
        if (!user.botStatus.ready) return res.json({ success: false, channels: [] });
        
        const client = userBots.get(user.id);
        if (!client) return res.json({ success: false, channels: [] });
        
        const guild = client.guilds.cache.get(user.guildId);
        if (!guild) return res.json({ success: false, channels: [] });
        
        const channels = guild.channels.cache
            .filter(c => c.type === ChannelType.GuildText || c.type === ChannelType.GuildCategory)
            .map(c => ({ id: c.id, name: c.name, type: c.type === ChannelType.GuildCategory ? 'category' : 'text' }));
        
        res.json({ success: true, channels });
    } catch (err) { 
        res.json({ success: false, channels: [] }); 
    }
});

app.get('/api/roles', requireAuth, async (req, res) => {
    try {
        const user = users.find(u => u.id === req.user.id);
        if (!user.botStatus.ready) return res.json({ success: false, roles: [] });
        
        const client = userBots.get(user.id);
        if (!client) return res.json({ success: false, roles: [] });
        
        const guild = client.guilds.cache.get(user.guildId);
        if (!guild) return res.json({ success: false, roles: [] });
        
        const roles = guild.roles.cache.map(r => ({ id: r.id, name: r.name }));
        res.json({ success: true, roles });
    } catch (err) { 
        res.json({ success: false, roles: [] }); 
    }
});

app.get('/api/logs', requireAuth, (req, res) => res.json({ success: true, logs: logs.slice(-50).reverse() }));

app.get('/api/admin/users', requireAuth, requireAdmin, (req, res) => res.json({ success: true, users: users.map(u => ({ ...u, password: undefined })) }));

app.get('/api/admin/keys', requireAuth, requireAdmin, (req, res) => res.json({ success: true, keys }));

app.post('/api/admin/ban-user', requireAuth, requireAdmin, (req, res) => {
    const { userId } = req.body;
    const user = users.find(u => u.id === userId);
    if (!user) return res.json({ success: false, message: 'User not found!' });
    user.banned = true;
    saveUsers();
    io.emit('userBanned', userId);
    addLog('warning', `Ban: ${user.username}`);
    res.json({ success: true, message: 'Banned!' });
});

app.post('/api/admin/unban-user', requireAuth, requireAdmin, (req, res) => {
    const { userId } = req.body;
    const user = users.find(u => u.id === userId);
    if (!user) return res.json({ success: false, message: 'User not found!' });
    user.banned = false;
    saveUsers();
    addLog('info', `Unban: ${user.username}`);
    res.json({ success: true, message: 'Unbanned!' });
});

app.post('/api/admin/delete-user', requireAuth, requireAdmin, (req, res) => {
    const { userId } = req.body;
    const index = users.findIndex(u => u.id === userId);
    if (index === -1) return res.json({ success: false, message: 'User not found!' });
    
    const user = users[index];
    const client = userBots.get(userId);
    if (client) {
        client.destroy();
        userBots.delete(userId);
    }
    
    users.splice(index, 1);
    saveUsers();
    addLog('warning', `Delete: ${user.username}`);
    res.json({ success: true, message: 'Deleted!' });
});

app.post('/api/admin/change-type', requireAuth, requireAdmin, (req, res) => {
    const { userId, accountType } = req.body;
    const user = users.find(u => u.id === userId);
    if (!user) return res.json({ success: false, message: 'User not found!' });
    user.accountType = accountType;
    saveUsers();
    addLog('info', `Account type changed: ${user.username} -> ${accountType}`);
    res.json({ success: true, message: 'Account type changed!' });
});

app.post('/api/admin/reset-password', requireAuth, requireAdmin, (req, res) => {
    const { userId, newPassword } = req.body;
    const user = users.find(u => u.id === userId);
    if (!user) return res.json({ success: false, message: 'User not found!' });
    user.password = bcrypt.hashSync(newPassword, 10);
    saveUsers();
    addLog('info', `Password reset: ${user.username}`);
    res.json({ success: true, message: 'Password reset!' });
});

app.post('/api/admin/create-key', requireAuth, requireAdmin, (req, res) => {
    const { type, amount } = req.body;
    const keyAmount = parseInt(amount) || 1;
    const createdKeys = [];
    
    for (let i = 0; i < keyAmount; i++) {
        const key = uuidv4();
        keys.push({ key, type, used: false, createdAt: new Date().toISOString() });
        createdKeys.push(key);
    }
    
    saveKeys();
    addLog('success', `${keyAmount} key(s) created: ${type}`);
    res.json({ success: true, message: `${keyAmount} key(s) created!`, keys: createdKeys });
});

app.post('/api/admin/delete-key', requireAuth, requireAdmin, (req, res) => {
    const { key } = req.body;
    const index = keys.findIndex(k => k.key === key);
    if (index === -1) return res.json({ success: false, message: 'Key not found!' });
    keys.splice(index, 1);
    saveKeys();
    addLog('info', `Key deleted: ${key}`);
    res.json({ success: true, message: 'Key deleted!' });
});

app.post('/api/upgrade', requireAuth, (req, res) => {
    const { key } = req.body;
    const keyData = keys.find(k => k.key === key && !k.used);
    if (!keyData) return res.json({ success: false, message: 'Invalid key!' });
    
    const user = users.find(u => u.id === req.user.id);
    user.accountType = keyData.type;
    keyData.used = true;
    saveUsers();
    saveKeys();
    
    addLog('success', `Upgrade: ${user.username} -> ${keyData.type}`);
    res.json({ success: true, message: 'Account upgraded!' });
});

app.post('/api/activity-test', requireAuth, async (req, res) => {
    if (req.user.accountType === 'free') return res.json({ success: false, message: 'Free account!' });
    const { channelId, time, note, title, description, timeFieldName, noteFieldName } = req.body;
    const user = users.find(u => u.id === req.user.id);
    
    try {
        if (!user.botStatus.ready) return res.json({ success: false, message: 'Bot offline!' });
        
        const client = userBots.get(user.id);
        if (!client) return res.json({ success: false, message: 'Bot not found!' });
        
        const guild = client.guilds.cache.get(user.guildId);
        if (!guild) return res.json({ success: false, message: 'Guild not found!' });
        
        const channel = guild.channels.cache.get(channelId);
        if (!channel) return res.json({ success: false, message: 'Channel not found!' });

        const embed = new EmbedBuilder()
            .setColor('#000000')
            .setTitle(title || user.activityTestMessages?.title || '⚡ Activity Test')
            .setDescription(description || user.activityTestMessages?.description || 'Join!')
            .addFields(
                { name: timeFieldName || user.activityTestMessages?.timeFieldName || '⏰ Time', value: time, inline: false },
                { name: noteFieldName || user.activityTestMessages?.noteFieldName || '📝 Note', value: note || user.activityTestMessages?.noteFieldValue || 'Don\'t forget!', inline: false }
            )
            .setTimestamp();

        const message = await channel.send({ embeds: [embed] });
        await message.react('✅');

        const activityMap = userActivityTests.get(user.id) || new Map();
        activityMap.set(message.id, {
            time,
            note,
            participants: new Set()
        });
        userActivityTests.set(user.id, activityMap);

        addLog('success', `Activity test sent for ${user.username}: ${channel.name}`);
        res.json({ success: true, message: 'Activity test sent!' });
    } catch (error) {
        addLog('error', `Activity test error for ${user.username}: ${error.message}`);
        res.json({ success: false, message: error.message });
    }
});

app.post('/api/activity-test/results', requireAuth, async (req, res) => {
    if (req.user.accountType === 'free') return res.json({ success: false, message: 'Free account!' });
    const { messageId } = req.body;
    const user = users.find(u => u.id === req.user.id);
    
    try {
        const activityMap = userActivityTests.get(user.id) || new Map();
        const data = activityMap.get(messageId);
        if (!data) return res.json({ success: false, message: 'Test not found!' });

        const client = userBots.get(user.id);
        if (!client || !user.botStatus.ready) return res.json({ success: false, message: 'Bot offline!' });

        const guild = client.guilds.cache.get(user.guildId);
        if (!guild) return res.json({ success: false, message: 'Guild not found!' });

        await guild.members.fetch();
        const participants = Array.from(data.participants)
            .map(id => guild.members.cache.get(id))
            .filter(m => m)
            .map(m => ({ id: m.id, tag: m.user.tag, username: m.user.username }));

        res.json({ success: true, participants, total: participants.length });
    } catch (error) {
        addLog('error', `Activity results error for ${user.username}: ${error.message}`);
        res.json({ success: false, message: error.message });
    }
});

app.post('/api/ingame-anc', requireAuth, async (req, res) => {
    if (req.user.accountType === 'free') return res.json({ success: false, message: 'Free account!' });
    const { channelId, numberOfPeople, ancText, title } = req.body;
    const user = users.find(u => u.id === req.user.id);
    
    try {
        if (!user.botStatus.ready) return res.json({ success: false, message: 'Bot offline!' });
        
        const client = userBots.get(user.id);
        if (!client) return res.json({ success: false, message: 'Bot not found!' });
        
        const guild = client.guilds.cache.get(user.guildId);
        if (!guild) return res.json({ success: false, message: 'Guild not found!' });
        
        const channel = guild.channels.cache.get(channelId);
        if (!channel) return res.json({ success: false, message: 'Channel not found!' });

        const embed = new EmbedBuilder()
            .setColor('#000000')
            .setTitle(title || user.ingameAncMessages?.title || '🎮 Ingame')
            .setDescription(ancText)
            .setTimestamp();

        const message = await channel.send({ embeds: [embed] });
        await message.react('✅');

        const ingameMap = userIngameAnnouncements.get(user.id) || new Map();
        ingameMap.set(message.id, {
            limit: parseInt(numberOfPeople),
            locked: false
        });
        userIngameAnnouncements.set(user.id, ingameMap);

        addLog('success', `Ingame sent for ${user.username}: ${channel.name}`);
        res.json({ success: true, message: 'Ingame announcement sent!' });
    } catch (error) {
        addLog('error', `Ingame error for ${user.username}: ${error.message}`);
        res.json({ success: false, message: error.message });
    }
});

app.post('/api/ticket/setup', requireAuth, async (req, res) => {
    if (req.user.accountType === 'free') return res.json({ success: false, message: 'Free account!' });
    const { ticketChannel, staffRole, ticketsCategory, closedCategory, embedTitle, embedDescription } = req.body;
    const user = users.find(u => u.id === req.user.id);
    
    try {
        if (!user.botStatus.ready) return res.json({ success: false, message: 'Bot offline!' });
        
        if (!user.ticketSettings) {
            user.ticketSettings = {};
        }
        
        user.ticketSettings.staffRole = staffRole;
        user.ticketSettings.ticketsCategory = ticketsCategory;
        user.ticketSettings.closedCategory = closedCategory;
        user.ticketSettings.embedTitle = embedTitle;
        user.ticketSettings.embedDescription = embedDescription;
        user.ticketSettings.ticketChannel = ticketChannel;
        saveUsers();

        const client = userBots.get(user.id);
        if (!client) return res.json({ success: false, message: 'Bot not found!' });
        
        const guild = client.guilds.cache.get(user.guildId);
        if (!guild) return res.json({ success: false, message: 'Guild not found!' });
        
        const channel = guild.channels.cache.get(ticketChannel);
        if (!channel) return res.json({ success: false, message: 'Channel not found!' });
        
        const embed = new EmbedBuilder()
            .setColor('#000000')
            .setTitle(embedTitle)
            .setDescription(embedDescription)
            .setTimestamp();

        const button = new ActionRowBuilder().addComponents(
            new ButtonBuilder()
                .setCustomId('create_ticket')
                .setLabel('Open Ticket')
                .setEmoji('🎫')
                .setStyle(ButtonStyle.Primary)
        );

        await channel.send({ embeds: [embed], components: [button] });
        addLog('success', `Ticket system setup for ${user.username}`);
        res.json({ success: true, message: 'Ticket system setup!' });
    } catch (error) {
        addLog('error', `Ticket setup error for ${user.username}: ${error.message}`);
        res.json({ success: false, message: error.message });
    }
});

app.post('/api/dm-anc', requireAuth, async (req, res) => {
    if (req.user.accountType === 'free') return res.json({ success: false, message: 'Free account!' });
    const { title, text } = req.body;
    const user = users.find(u => u.id === req.user.id);
    
    try {
        if (!user.botStatus.ready) return res.json({ success: false, message: 'Bot offline!' });
        
        const client = userBots.get(user.id);
        if (!client) return res.json({ success: false, message: 'Bot not found!' });
        
        const guild = client.guilds.cache.get(user.guildId);
        if (!guild) return res.json({ success: false, message: 'Guild not found!' });

        await guild.members.fetch();
        const members = Array.from(guild.members.cache.values()).filter(m => !m.user.bot);

        const embed = new EmbedBuilder()
            .setColor('#000000')
            .setTitle(title)
            .setDescription(text)
            .setTimestamp();

        let successCount = 0;
        let failCount = 0;

        for (const member of members) {
            try {
                await member.send({ embeds: [embed] });
                successCount++;
                await new Promise(resolve => setTimeout(resolve, 1000));
            } catch (error) {
                failCount++;
                console.error(`DM failed for ${member.user.tag}: ${error.message}`);
            }
        }

        addLog('success', `DM sent for ${user.username}: ${successCount} success, ${failCount} failed`);
        res.json({ success: true, message: `DM sent! ${successCount} successful, ${failCount} failed` });
    } catch (error) {
        addLog('error', `DM error for ${user.username}: ${error.message}`);
        res.json({ success: false, message: error.message });
    }
});

app.post('/api/give-role', requireAuth, async (req, res) => {
    if (req.user.accountType === 'free') return res.json({ success: false, message: 'Free account!' });
    const { channelId, roleId, emoji, buttonText, embedTitle, embedDescription } = req.body;
    const user = users.find(u => u.id === req.user.id);
    
    try {
        if (!user.botStatus.ready) return res.json({ success: false, message: 'Bot offline!' });
        
        const client = userBots.get(user.id);
        if (!client) return res.json({ success: false, message: 'Bot not found!' });
        
        const guild = client.guilds.cache.get(user.guildId);
        if (!guild) return res.json({ success: false, message: 'Guild not found!' });
        
        const channel = guild.channels.cache.get(channelId);
        if (!channel) return res.json({ success: false, message: 'Channel not found!' });

        const embed = new EmbedBuilder()
            .setColor('#000000')
            .setTitle(embedTitle)
            .setDescription(embedDescription)
            .setTimestamp();

        const button = new ActionRowBuilder().addComponents(
            new ButtonBuilder()
                .setCustomId(`give_role_${roleId}`)
                .setLabel(buttonText)
                .setEmoji(emoji)
                .setStyle(ButtonStyle.Primary)
        );

        await channel.send({ embeds: [embed], components: [button] });
        addLog('success', `Role button created for ${user.username}: ${channel.name}`);
        res.json({ success: true, message: 'Role button created!' });
    } catch (error) {
        addLog('error', `Give role error for ${user.username}: ${error.message}`);
        res.json({ success: false, message: error.message });
    }
});

// Guard API endpoints
app.post('/api/guard/radar/add-role', requireAuth, (req, res) => {
    if (req.user.accountType === 'free') return res.json({ success: false, message: 'Free account!' });
    const { roleId, roleName } = req.body;
    const user = users.find(u => u.id === req.user.id);
    
    if (!user.guardSettings) user.guardSettings = { radar: { roles: [], action: 'kick' } };
    if (!user.guardSettings.radar.roles.find(r => r.id === roleId)) {
        user.guardSettings.radar.roles.push({ id: roleId, name: roleName });
        saveUsers();
        addLog('success', `Radar role added for ${user.username}: ${roleName}`);
        res.json({ success: true, message: 'Radar role added!' });
    } else {
        res.json({ success: false, message: 'This role is already in radar list!' });
    }
});

app.post('/api/guard/radar/remove-role', requireAuth, (req, res) => {
    if (req.user.accountType === 'free') return res.json({ success: false, message: 'Free account!' });
    const { roleId } = req.body;
    const user = users.find(u => u.id === req.user.id);
    
    if (!user.guardSettings) user.guardSettings = { radar: { roles: [], action: 'kick' } };
    const index = user.guardSettings.radar.roles.findIndex(r => r.id === roleId);
    if (index !== -1) {
        const removedRole = user.guardSettings.radar.roles.splice(index, 1)[0];
        saveUsers();
        addLog('success', `Radar role removed for ${user.username}: ${removedRole.name}`);
        res.json({ success: true, message: 'Radar role removed!' });
    } else {
        res.json({ success: false, message: 'Role not found!' });
    }
});

app.get('/api/guard/radar/roles', requireAuth, (req, res) => {
    const user = users.find(u => u.id === req.user.id);
    const roles = user.guardSettings?.radar?.roles || [];
    res.json({ success: true, roles });
});

app.post('/api/guard/radar/settings', requireAuth, (req, res) => {
    if (req.user.accountType === 'free') return res.json({ success: false, message: 'Free account!' });
    const { radarAction } = req.body;
    const user = users.find(u => u.id === req.user.id);
    
    if (!user.guardSettings) user.guardSettings = { radar: { roles: [], action: 'kick' } };
    user.guardSettings.radar.action = radarAction;
    saveUsers();
    
    addLog('success', `Radar settings updated for ${user.username}: ${radarAction}`);
    res.json({ success: true, message: 'Radar settings saved!' });
});

app.post('/api/guard/channel-protection', requireAuth, (req, res) => {
    if (req.user.accountType === 'free') return res.json({ success: false, message: 'Free account!' });
    const { channelCreateLimit, channelDeleteLimit, channelAction, channelAssignRoleId, channelDeleteAction, channelDeleteAssignRoleId, channelResetTime } = req.body;
    const user = users.find(u => u.id === req.user.id);
    
    if (!user.guardSettings) user.guardSettings = {};
    user.guardSettings.channelProtection = {
        createLimit: parseInt(channelCreateLimit),
        deleteLimit: parseInt(channelDeleteLimit),
        resetTime: parseInt(channelResetTime) * 60000, // Convert minutes to milliseconds
        action: channelAction,
        assignRole: channelAssignRoleId || '',
        deleteAction: channelDeleteAction || '',
        deleteAssignRole: channelDeleteAssignRoleId || ''
    };
    saveUsers();
    
    addLog('success', `Channel protection updated for ${user.username}`);
    res.json({ success: true, message: 'Channel protection settings saved!' });
});

app.post('/api/guard/member-protection', requireAuth, (req, res) => {
    if (req.user.accountType === 'free') return res.json({ success: false, message: 'Free account!' });
    const { banLimit, kickLimit, timeoutLimit, memberAction, memberAssignRoleId, memberResetTime } = req.body;
    const user = users.find(u => u.id === req.user.id);
    
    if (!user.guardSettings) user.guardSettings = {};
    user.guardSettings.memberProtection = {
        banLimit: parseInt(banLimit),
        kickLimit: parseInt(kickLimit),
        timeoutLimit: parseInt(timeoutLimit),
        resetTime: parseInt(memberResetTime) * 60000, // Convert minutes to milliseconds
        action: memberAction,
        assignRole: memberAssignRoleId || ''
    };
    saveUsers();
    
    addLog('success', `Member protection updated for ${user.username}`);
    res.json({ success: true, message: 'Member protection settings saved!' });
});

app.post('/api/guard/role-protection', requireAuth, (req, res) => {
    if (req.user.accountType === 'free') return res.json({ success: false, message: 'Free account!' });
    const { roleCreateLimit, roleDeleteLimit, roleAction, roleAssignRoleId, roleResetTime } = req.body;
    const user = users.find(u => u.id === req.user.id);
    
    if (!user.guardSettings) user.guardSettings = {};
    user.guardSettings.roleProtection = {
        createLimit: parseInt(roleCreateLimit),
        deleteLimit: parseInt(roleDeleteLimit),
        resetTime: parseInt(roleResetTime) * 60000, // Convert minutes to milliseconds
        action: roleAction,
        assignRole: roleAssignRoleId || ''
    };
    saveUsers();
    
    addLog('success', `Role protection updated for ${user.username}`);
    res.json({ success: true, message: 'Role protection settings saved!' });
});

app.post('/api/guard/log-settings', requireAuth, (req, res) => {
    if (req.user.accountType === 'free') return res.json({ success: false, message: 'Free account!' });
    const { guardLogChannel } = req.body;
    const user = users.find(u => u.id === req.user.id);
    
    if (!user.guardSettings) user.guardSettings = {};
    user.guardSettings.logChannel = guardLogChannel;
    saveUsers();
    
    addLog('success', `Guard log channel set for ${user.username}`);
    res.json({ success: true, message: 'Guard log channel set!' });
});

app.get('/api/guard/logs', requireAuth, (req, res) => {
    if (req.user.accountType === 'free') return res.json({ success: false, message: 'Free account!' });
    const user = users.find(u => u.id === req.user.id);
    
    const guardLogs = user.guardLogs || [];
    res.json({ success: true, logs: guardLogs.slice(-50).reverse() });
});

// Toggle API endpoints
app.post('/api/guard/channel-toggle', requireAuth, (req, res) => {
    if (req.user.accountType === 'free') return res.json({ success: false, message: 'Free account!' });
    const { enabled } = req.body;
    const user = users.find(u => u.id === req.user.id);
    
    if (!user.guardSettings) user.guardSettings = {};
    if (!user.guardSettings.channelProtection) {
        user.guardSettings.channelProtection = {
            createLimit: 3,
            deleteLimit: 2,
            resetTime: 3600000,
            action: 'kick',
            assignRole: '',
            enabled: false
        };
    }
    
    user.guardSettings.channelProtection.enabled = enabled;
    saveUsers();
    
    const status = enabled ? 'enabled' : 'disabled';
    addLog('success', `Channel protection ${status} for ${user.username}`);
    res.json({ success: true, message: `Channel protection ${status}!` });
});

app.post('/api/guard/member-toggle', requireAuth, (req, res) => {
    if (req.user.accountType === 'free') return res.json({ success: false, message: 'Free account!' });
    const { enabled } = req.body;
    const user = users.find(u => u.id === req.user.id);
    
    if (!user.guardSettings) user.guardSettings = {};
    if (!user.guardSettings.memberProtection) {
        user.guardSettings.memberProtection = {
            banLimit: 2,
            kickLimit: 5,
            timeoutLimit: 10,
            resetTime: 3600000,
            action: 'kick',
            assignRole: '',
            enabled: false
        };
    }
    
    user.guardSettings.memberProtection.enabled = enabled;
    saveUsers();
    
    const status = enabled ? 'enabled' : 'disabled';
    addLog('success', `Member protection ${status} for ${user.username}`);
    res.json({ success: true, message: `Member protection ${status}!` });
});

app.post('/api/guard/role-toggle', requireAuth, (req, res) => {
    if (req.user.accountType === 'free') return res.json({ success: false, message: 'Free account!' });
    const { enabled } = req.body;
    const user = users.find(u => u.id === req.user.id);
    
    if (!user.guardSettings) user.guardSettings = {};
    if (!user.guardSettings.roleProtection) {
        user.guardSettings.roleProtection = {
            createLimit: 3,
            deleteLimit: 2,
            resetTime: 3600000,
            action: 'kick',
            assignRole: '',
            enabled: false
        };
    }
    
    user.guardSettings.roleProtection.enabled = enabled;
    saveUsers();
    
    const status = enabled ? 'enabled' : 'disabled';
    addLog('success', `Role protection ${status} for ${user.username}`);
    res.json({ success: true, message: `Role protection ${status}!` });
});

// Helper function to add guard log
function addGuardLog(userId, type, message) {
    const user = users.find(u => u.id === userId);
    if (!user) return;
    
    if (!user.guardLogs) user.guardLogs = [];
    
    user.guardLogs.push({
        type,
        message,
        timestamp: new Date().toISOString()
    });
    
    // Keep only last 100 logs
    if (user.guardLogs.length > 100) {
        user.guardLogs.shift();
    }
    
    saveUsers();
}

function tryListen(portIndex = 0) {
    if (portIndex >= PORTS.length) {
        console.error('❌ All ports are busy! Please free up a port and try again.');
        process.exit(1);
    }
    
    const currentPort = PORTS[portIndex];
    server.listen(currentPort, '0.0.0.0')
        .on('listening', () => {
            PORT = currentPort;
            console.log(`🚀 Port: ${PORT}`);
            console.log(`🌐 http://localhost:${PORT}`);
            addLog('success', `Panel started - Port: ${PORT}`);
        })
        .on('error', (err) => {
            if (err.code === 'EADDRINUSE') {
                console.log(`⚠️  Port ${currentPort} is busy, trying next port...`);
                tryListen(portIndex + 1);
            } else {
                console.error('❌ Server error:', err);
                process.exit(1);
            }
        });
}

tryListen();
