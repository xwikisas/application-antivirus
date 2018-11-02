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

import java.util.Arrays;
import java.util.Date;
import java.util.List;

import javax.inject.Provider;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.xwiki.model.internal.reference.DefaultStringEntityReferenceSerializer;
import org.xwiki.model.internal.reference.DefaultSymbolScheme;
import org.xwiki.model.reference.AttachmentReference;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.LocalDocumentReference;
import org.xwiki.security.authorization.AuthorizationManager;
import org.xwiki.test.annotation.ComponentList;
import org.xwiki.test.mockito.MockitoComponentMockingRule;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.doc.XWikiAttachment;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xwiki.antivirus.AntivirusLog;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link DefaultAntivirusLog}.
 *
 * @version $Id$
 */
@ComponentList({DefaultStringEntityReferenceSerializer.class, DefaultSymbolScheme.class})
public class DefaultAntivirusLogTest
{
    @Rule
    public final MockitoComponentMockingRule<AntivirusLog> mocker =
        new MockitoComponentMockingRule<>(DefaultAntivirusLog.class);

    private AntivirusLog antivirusLog;

    private Provider<XWikiContext> contextProvider;

    private XWiki xwiki;

    private XWikiContext context;

    private XWikiDocument attachmentDoc;

    private DocumentReference attachmentDocReference = new DocumentReference("wiki", "Space", "Page");

    private XWikiDocument incidentDoc;

    private BaseObject object;

    private DocumentReference incidentDocReference = new DocumentReference("wiki", "AntivirusLog", "1234");

    private XWikiAttachment attachment;

    private String fileName = "file.ext";

    private AttachmentReference attachmentReference;

    private Date attachmentDate = new Date();

    private DocumentReference attachmentAuthorReference = new DocumentReference("wiki", "XWiki", "user");

    @Before
    public void setUp() throws Exception
    {
        antivirusLog = mocker.getComponentUnderTest();

        context = mock(XWikiContext.class);
        when(context.getMainXWiki()).thenReturn("wiki");

        contextProvider = mocker.getInstance(XWikiContext.TYPE_PROVIDER);
        when(contextProvider.get()).thenReturn(context);

        xwiki = mock(XWiki.class);
        when(context.getWiki()).thenReturn(xwiki);

        incidentDoc = mock(XWikiDocument.class);
        when(incidentDoc.isNew()).thenReturn(true);

        when(xwiki.getDocument(any(DocumentReference.class), eq(context))).then(new Answer<XWikiDocument>()
        {
            @Override
            public XWikiDocument answer(InvocationOnMock invocation) throws Throwable
            {
                incidentDocReference = invocation.getArgument(0);
                return incidentDoc;
            }
        });

        object = mock(BaseObject.class);
        when(incidentDoc.newXObject(new LocalDocumentReference("Antivirus", "AntivirusIncidentClass"), context))
            .thenReturn(object);

        attachmentDoc = mock(XWikiDocument.class);
        when(attachmentDoc.getDocumentReference()).thenReturn(attachmentDocReference);

        attachmentReference = new AttachmentReference(fileName, attachmentDocReference);

        attachment = mock(XWikiAttachment.class);
        when(attachment.getReference()).thenReturn(attachmentReference);
        when(attachment.getFilename()).thenReturn(fileName);
        when(attachment.getDoc()).thenReturn(attachmentDoc);
        when(attachment.getDate()).thenReturn(attachmentDate);
        when(attachment.getAuthorReference()).thenReturn(attachmentAuthorReference);
    }

    @Test
    public void log() throws Exception
    {
        List<String> infections = Arrays.asList("bad", "virus");
        String action = "blocked";
        String detectionContext = "upload";
        String engineHint = "virusBeGone";

        antivirusLog.log(attachment, infections, action, detectionContext, engineHint);

        // Check that the generated incident is locate in the AntivirusLog space.
        assertEquals("wiki", incidentDocReference.getLastSpaceReference().getParent().getName());
        assertEquals("AntivirusLog", incidentDocReference.getLastSpaceReference().getName());

        verify(object, times(1)).set("attachmentName", fileName, context);
        verify(object, times(1)).set("attachmentInfections", infections, context);
        verify(object, times(1)).set("incidentAction", action, context);
        // We can't verify the exact date generated during the test.
        verify(object, times(1)).set(eq("incidentDate"), any(Date.class), eq(context));
        verify(object, times(1)).set("incidentContext", detectionContext, context);
        verify(object, times(1)).set("attachmentDocument", "wiki:Space.Page", context);
        verify(object, times(1)).set("attachmentDate", attachmentDate, context);
        verify(object, times(1)).set("attachmentAuthor", "wiki:XWiki.user", context);
        verify(object, times(1)).set("engine", engineHint, context);

        // Check that the superadmin user is used as author of the incident.
        verify(incidentDoc, times(1)).setAuthorReference(
            new DocumentReference(context.getMainXWiki(), XWiki.SYSTEM_SPACE, AuthorizationManager.SUPERADMIN_USER));

        verify(xwiki, times(1)).saveDocument(incidentDoc, context);
    }
}
