/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package com.xwiki.antivirus.internal;

import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;
import javax.mail.Session;
import javax.mail.internet.MimeMessage;

import org.apache.commons.collections4.IteratorUtils;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.manager.ComponentManager;
import org.xwiki.component.phase.Initializable;
import org.xwiki.component.phase.InitializationException;
import org.xwiki.mail.MailListener;
import org.xwiki.mail.MailSender;
import org.xwiki.mail.MimeMessageFactory;
import org.xwiki.mail.SessionFactory;
import org.xwiki.model.reference.DocumentReference;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.api.Attachment;
import com.xpn.xwiki.doc.XWikiAttachment;
import com.xwiki.antivirus.AntivirusLog;
import com.xwiki.antivirus.AntivirusReportSender;
import com.xwiki.antivirus.AntivirusScan;

/**
 * Default implementation for {@link AntivirusReportSender} using the Mail API.
 *
 * @version $Id$
 */
@Component
@Singleton
public class DefaultAntivirusReportSender implements AntivirusReportSender, Initializable
{
    @Inject
    @Named("usersandgroups")
    private MimeMessageFactory<Iterator<MimeMessage>> usersAndGroupsMessageFactory;

    @Inject
    private SessionFactory sessionFactory;

    @Inject
    private MailSender mailSender;

    @Inject
    private Provider<XWikiContext> contextProvider;

    @Inject
    private ComponentManager componentManager;

    @Inject
    AntivirusLog antivirusLog;

    private DocumentReference templateReference;

    private List<DocumentReference> notificationGroupReferences;

    @Override
    public void initialize() throws InitializationException
    {
        String mainWikiName = contextProvider.get().getMainXWiki();

        this.templateReference = new DocumentReference(mainWikiName, "Antivirus", "ScheduledScanReportMailTemplate");

        this.notificationGroupReferences =
            Collections.singletonList(new DocumentReference(mainWikiName, "XWiki", "XWikiAdminGroup"));
    }

    @Override
    public void sendReport(AntivirusScan antivirusScan) throws Exception
    {
        XWikiContext context = contextProvider.get();
        XWiki xwiki = context.getWiki();

        // Generate the needed Attachment to String Collection maps from the AntivirusIncident documents.
        Map<String, Map<Attachment, Collection<String>>> incidents =
            getIncidents(antivirusScan.getStartDate(), context);
        // API classes are easier to use with velocity in the template.

        Map<String, Object> velocityVariables = new HashMap<>();
        velocityVariables.put("deletedInfectedAttachments", incidents.getOrDefault("deleted", Collections.EMPTY_MAP));
        velocityVariables.put("deleteFailedInfectedAttachments",
            incidents.getOrDefault("deleteFailed", Collections.EMPTY_MAP));
        velocityVariables.put("scanFailedAttachments", incidents.getOrDefault("scanFailed", Collections.EMPTY_MAP));
        velocityVariables.put("filesScanned", antivirusScan.getScannedFiles());
        velocityVariables.put("wikiUrl", xwiki.getExternalURL("Main.WebHome", "view", context));
        velocityVariables.put("adminUrl",
            xwiki.getExternalURL("XWiki.XWikiPreferences", "admin", "editor=globaladmin&section=antivirus", context));
        velocityVariables.put("startDate", antivirusScan.getStartDate());
        velocityVariables.put("endDate", antivirusScan.getEndData());

        Map<String, Object> templateFactoryParameters = new HashMap<>();
        templateFactoryParameters.put("type", "antivirusReport");
        templateFactoryParameters.put("language", xwiki.getDefaultLocale(context).toString());
        templateFactoryParameters.put("velocityVariables", velocityVariables);

        Map<String, Object> usersAndGroupsFactoryParameters = new HashMap<>();
        usersAndGroupsFactoryParameters.put("hint", "template");
        usersAndGroupsFactoryParameters.put("source", templateReference);
        usersAndGroupsFactoryParameters.put("parameters", templateFactoryParameters);

        Map<String, List<DocumentReference>> usersOrGroups = new HashMap<>();
        usersOrGroups.put("groups", notificationGroupReferences);

        Session session = sessionFactory.create(Collections.emptyMap());

        Iterator<MimeMessage> messages =
            usersAndGroupsMessageFactory.createMessage(usersOrGroups, usersAndGroupsFactoryParameters);

        MailListener mailListener = this.componentManager.getInstance(MailListener.class, "database");

        mailSender.sendAsynchronously(IteratorUtils.asIterable(messages), session, mailListener);
    }

    private Map<String, Map<Attachment, Collection<String>>> getIncidents(Date startDate, XWikiContext context)
        throws Exception
    {
        Map<String, Map<XWikiAttachment, Collection<String>>> incidents = antivirusLog.getIncidents(startDate);

        Map<String, Map<Attachment, Collection<String>>> modifiedIncidents = new HashMap<>();

        for (Map.Entry<String, Map<XWikiAttachment, Collection<String>>> entry : incidents.entrySet()) {
            Map<Attachment, Collection<String>> incidentsGroup = entry.getValue().entrySet().stream().collect(
                Collectors.toMap(e -> new Attachment(e.getKey().getDoc().newDocument(context), e.getKey(), context),
                    Map.Entry::getValue));
            modifiedIncidents.put(entry.getKey(), incidentsGroup);
        }
        return modifiedIncidents;
    }
}
