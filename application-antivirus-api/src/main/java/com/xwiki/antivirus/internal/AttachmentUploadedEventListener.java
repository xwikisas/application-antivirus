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

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.AttachmentDiff;
import com.xpn.xwiki.doc.XWikiAttachment;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xwiki.antivirus.*;
import com.xwiki.licensing.Licensor;
import org.slf4j.Logger;
import org.xwiki.bridge.event.DocumentCreatingEvent;
import org.xwiki.bridge.event.DocumentUpdatingEvent;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.manager.ComponentLookupException;
import org.xwiki.component.manager.ComponentManager;
import org.xwiki.diff.Delta.Type;
import org.xwiki.model.reference.AttachmentReference;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.observation.AbstractEventListener;
import org.xwiki.observation.event.CancelableEvent;
import org.xwiki.observation.event.Event;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;
import java.util.*;

/**
 * Listener for whenever an attachment is added to or updated on a document. Each time, each affected attachment is
 * scanned and, in case a virus is detected, the event and the save operation itself will be cancel.
 *
 * @version $Id$
 */
@Component
@Named("com.xwiki.antivirus.internal.AttachmentUploadedEventListener")
@Singleton
public class AttachmentUploadedEventListener extends AbstractEventListener {
    @Inject
    private ComponentManager componentManager;

    @Inject
    private AntivirusConfiguration antivirusConfiguration;

    /**
     * Lazy-load the Licensor because it needs the database to be ready (it needs the instance id in order to validate
     * the licenses and the instance id is stored in the database).
     */
    @Inject
    private Provider<Licensor> licensorProvider;

    @Inject
    private AntivirusLog antivirusLog;

    @Inject
    private Logger logger;

    /**
     * Default constructor.
     */
    public AttachmentUploadedEventListener() {
        super(AttachmentUploadedEventListener.class.getName(),
                Arrays.asList(new DocumentUpdatingEvent(), new DocumentCreatingEvent()));
    }

    @Override
    public void onEvent(Event event, Object source, Object data) {
        XWikiDocument doc = (XWikiDocument) source;
        XWikiContext context = (XWikiContext) data;

        // Skip if scanning is disabled.
        if (!antivirusConfiguration.isEnabled()) {
            if (logger.isDebugEnabled()) {
                logger.debug(
                        "Skipping attachment scan for event [{}] by user [{}] on document [{}]. Antivirus is disabled.",
                        event.getClass().getName(), context.getUserReference(), doc.getDocumentReference());
            }
            return;
        }

        // doc.getAttachmentDiff() seems to have side-effects on the (original) doc on which it is called (on its
        // attachments, to be more precise). In order to not disturb other handlers in the event handling chain, we
        // choose to play it safe and work with a clone.
        // See https://jira.xwiki.org/browse/XWIKI-18775
        XWikiDocument safeDoc = doc.clone();
        safeDoc.setOriginalDocument(doc.getOriginalDocument().clone());

        List<XWikiAttachment> attachmentsToScan = getAttachmentsToScan(event, safeDoc, context);

        // Skip if no attachments were added or modified.
        if (attachmentsToScan.isEmpty()) {
            return;
        }

        // Skip if the license has expired.
        if (!licensorProvider.get()
                .hasLicensure(new DocumentReference(context.getMainXWiki(), "Antivirus", "ConfigurationClass"))) {
            logger.warn("Skipping attachment scan for event [{}] by user [{}] on document [{}]. "
                            + "No valid Antivirus license has been found. Please visit the 'Licenses' section in Administration.",
                    event.getClass().getName(), context.getUserReference(), safeDoc.getDocumentReference());
            return;
        }

        // Get the configured antivirus engine.
        AntivirusEngine antivirus = null;
        try {
            antivirus =
                    componentManager.getInstance(AntivirusEngine.class, antivirusConfiguration.getDefaultEngineName());
        } catch (ComponentLookupException e) {
            logger.error(
                    "Failed to load antivirus engine [{}] to scan attachments for event [{}] by user [{}] on document [{}]",
                    antivirusConfiguration.getDefaultEngineName(), event.getClass().getName(), context.getUserReference(),
                    safeDoc.getDocumentReference(), e);
            return;
        }

        Map<AttachmentReference, Collection<String>> infectedAttachments =
                scan(event, context, antivirus, attachmentsToScan);

        // Cancel the event if we have detected any infections.
        if (infectedAttachments.size() > 0) {
            ((CancelableEvent) event)
                    .cancel(String.format("Virus or malware infections found for attachments [%s] uploaded by user [%s]",
                            infectedAttachments, context.getUserReference()));
        }
    }

    private Map<AttachmentReference, Collection<String>> scan(Event event, XWikiContext context,
                                                              AntivirusEngine antivirus, List<XWikiAttachment> attachmentsToScan) {
        // Scan each attachment and build the list of infections.
        Map<AttachmentReference, Collection<String>> infectedAttachments = new HashMap<>();
        for (XWikiAttachment attachment : attachmentsToScan) {
            try {
                // Compare the attachment size (bytes) to the maximum configured size (MB). Conversion needed.
                long attachmentSize = attachment.getContentLongSize(context);
                int maxFileSize = antivirusConfiguration.getMaxFileSize();
                if (attachmentSize > maxFileSize * 1_000_000L) {
                    logger.warn(
                            "Attachment [{}] is larger than [{}MB] and will be skipped during event [{}] by user [{}]."
                                    + " The file will be scanned during the scheduled scan.",
                            attachment.getReference(), maxFileSize, event.getClass().getName(), context.getUserReference());
                    continue;
                }
                ScanResult scanResult = antivirus.scan(attachment);
                if (scanResult.isClean()) {
                    continue;
                }

                // Infection found.
                infectedAttachments.put(attachment.getReference(), scanResult.getfoundViruses());
                logger.warn("Attachment [{}] found infected with [{}] during event [{}] by user [{}]",
                        attachment.getReference(), scanResult.getfoundViruses(), event.getClass().getName(),
                        context.getUserReference());

                // Save the incident in the log.
                antivirusLog.log(attachment, scanResult.getfoundViruses(), "blocked", "upload",
                        antivirusConfiguration.getDefaultEngineName());
            } catch (AntivirusException | XWikiException e) {
                logger.error("Failed to scan attachment [{}] during event [{}] by user [{}]", attachment.getReference(),
                        event.getClass().getName(), context.getUserReference(), e);
            }
        }
        return infectedAttachments;
    }

    private List<XWikiAttachment> getAttachmentsToScan(Event event, XWikiDocument doc, XWikiContext context) {
        List<XWikiAttachment> attachmentsToScan = new ArrayList<>();

        if (event instanceof DocumentUpdatingEvent) {
            XWikiDocument originalDoc = doc.getOriginalDocument();

            for (AttachmentDiff diff : doc.getAttachmentDiff(originalDoc, doc, context)) {
                // Scan only added or updated attachments from the new version of the document.
                if (diff.getType() == Type.INSERT || diff.getType() == Type.CHANGE) {
                    attachmentsToScan.add(diff.getNewAttachment());
                }
            }
        } else if (event instanceof DocumentCreatingEvent) {
            // New document = new attachments.
            attachmentsToScan = doc.getAttachmentList();
        }

        return attachmentsToScan;
    }
}
