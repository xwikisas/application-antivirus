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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.apache.commons.lang3.RandomStringUtils;
import org.xwiki.component.annotation.Component;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.model.reference.LocalDocumentReference;
import org.xwiki.query.Query;
import org.xwiki.query.QueryException;
import org.xwiki.query.QueryManager;
import org.xwiki.security.authorization.AuthorizationManager;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiAttachment;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xwiki.antivirus.AntivirusException;
import com.xwiki.antivirus.AntivirusLog;

/**
 * Default implementation for {@link AntivirusLog}, saving incidents in their own pages under a common space.
 *
 * @version $Id$
 */
@Component
@Singleton
public class DefaultAntivirusLog implements AntivirusLog
{
    public static final LocalDocumentReference INCIDENT_CLASS_REFERENCE =
        new LocalDocumentReference("Antivirus", "AntivirusIncidentClass");

    @Inject
    private Provider<XWikiContext> contextProvider;

    @Inject
    private EntityReferenceSerializer<String> serializer;

    @Inject
    private QueryManager queryManager;

    @Inject
    private DocumentReferenceResolver<String> resolver;

    @Override
    public void log(XWikiAttachment attachment, Collection<String> infections, String action, String detectionContext,
        String engineHint) throws AntivirusException
    {
        XWikiContext context = contextProvider.get();
        XWiki xwiki = context.getWiki();

        try {
            XWikiDocument document = generateDocument(context, xwiki);

            BaseObject object = document.newXObject(INCIDENT_CLASS_REFERENCE, context);

            object.set("attachmentName", attachment.getFilename(), context);
            object.set("attachmentInfections", new ArrayList<>(infections), context);
            object.set("incidentAction", action, context);
            object.set("incidentDate", new Date(), context);
            object.set("incidentContext", detectionContext, context);
            object.set("attachmentDocument", serializer.serialize(attachment.getDoc().getDocumentReference()), context);
            object.set("attachmentDate", attachment.getDate(), context);
            object.set("attachmentAuthor", serializer.serialize(attachment.getAuthorReference()), context);
            object.set("engine", engineHint, context);

            xwiki.saveDocument(document, context);
        } catch (Exception e) {
            throw new AntivirusException(
                String.format("Failed to save incident for [%s], infections %s, context [%s], action [%s]",
                    attachment.getDoc().getDocumentReference(), infections, detectionContext, action),
                e);
        }
    }

    @Override
    public Map<String, Map<XWikiAttachment, Collection<String>>> getIncidents(Date date)
        throws QueryException, XWikiException
    {
        // All the incidents are saved only on the main wiki, as the application can only be installed on the main wiki.
        XWikiContext context = contextProvider.get();
        List<String> incidentDocNames = queryManager
            .createQuery("where doc.object(Antivirus.AntivirusIncidentClass).incidentDate > :scanStartDate", Query.XWQL)
            .setWiki(context.getMainXWiki())
            .bindValue("scanStartDate", date)
            .execute();

        Map<String, Map<XWikiAttachment, Collection<String>>> incidents = new HashMap<>();
        for (String incidentDocName : incidentDocNames) {
            DocumentReference reference = resolver.resolve(incidentDocName, context.getMainXWiki());
            XWikiDocument doc = context.getWiki().getDocument(reference, context);
            BaseObject incidentObj = doc.getXObject(INCIDENT_CLASS_REFERENCE);
            DocumentReference docRef = resolver.resolve(incidentObj.getStringValue("attachmentDocument"));
            XWikiDocument document = context.getWiki().getDocument(docRef, context);
            XWikiAttachment attachment = new XWikiAttachment(document, incidentObj.getStringValue("attachmentName"));
            String incidentAction = incidentObj.getStringValue("incidentAction");
            incidents.putIfAbsent(incidentAction, new HashMap<>());
            incidents.get(incidentAction).put(attachment, incidentObj.getListValue("attachmentInfections"));
        }
        return incidents;
    }

    private XWikiDocument generateDocument(XWikiContext context, XWiki xwiki) throws XWikiException
    {
        XWikiDocument document = null;

        DocumentReference logHomepage = new DocumentReference(context.getMainXWiki(), "AntivirusLog", "WebHome");

        do {
            // Include a random element in the document name to avoid the edge case where multiple incidents would be
            // logged in the exact same time.
            String documentName =
                String.format("%s-%s", System.currentTimeMillis(), RandomStringUtils.randomAlphanumeric(5));

            DocumentReference documentReference =
                new DocumentReference(documentName, logHomepage.getLastSpaceReference());

            document = xwiki.getDocument(documentReference, context);

            // Use the default superadmin user as document author.
            document.setAuthorReference(new DocumentReference(context.getMainXWiki(), XWiki.SYSTEM_SPACE,
                AuthorizationManager.SUPERADMIN_USER));

            // Set the AntivirusLog homepage as parent, for older XWiki versions where this is relevant.
            document.setParentReference(logHomepage);
        } while (!document.isNew());

        return document;
    }
}
