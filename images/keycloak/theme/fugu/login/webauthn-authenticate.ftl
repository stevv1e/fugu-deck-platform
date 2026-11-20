<#import "template.ftl" as layout>
<#import "buttons.ftl" as buttons>
<@layout.registrationLayout displayInfo=(realm.registrationAllowed && !registrationDisabled??); section>
    <#if section = "title">
        title
    <#elseif section = "header">
        ${msg("webauthn-login-title")}
    <#elseif section = "form">
        <div id="kc-form-webauthn" class="${properties.kcFormClass!}">
            <form id="webauth" action="${url.loginAction}" method="post" hidden="hidden">
                <input type="hidden" id="clientDataJSON" name="clientDataJSON"/>
                <input type="hidden" id="authenticatorData" name="authenticatorData"/>
                <input type="hidden" id="signature" name="signature"/>
                <input type="hidden" id="credentialId" name="credentialId"/>
                <input type="hidden" id="userHandle" name="userHandle"/>
                <input type="hidden" id="error" name="error"/>
            </form>

            <#if authenticators??>
                <form id="authn_select" class="${properties.kcFormClass!}" hidden="hidden">
                    <#list authenticators.authenticators as authenticator>
                        <input type="hidden" name="authn_use_chk" value="${authenticator.credentialId}"/>
                    </#list>
                </form>

                <#if shouldDisplayAuthenticators?? && shouldDisplayAuthenticators>
                    <#if authenticators.authenticators?size gt 1>
                        <p>${msg("webauthn-available-authenticators")}</p>
                    </#if>
                    <ul class="${properties.kcSelectAuthListClass!}" role="list">
                        <#list authenticators.authenticators as authenticator>
                            <li class="${properties.kcSelectAuthListItemWrapperClass!}">
                                <div class="${properties.kcSelectAuthListItemHeadingClass!}">${authenticator.label}</div>
                                <#if authenticator.authenticatorProvider?? && authenticator.authenticatorProvider?has_content>
                                    <div class="${properties.kcSelectAuthListItemSubtitleClass!}">${authenticator.authenticatorProvider}</div>
                                <#elseif authenticator.transports?? && authenticator.transports.displayNameProperties?has_content>
                                    <div class="${properties.kcSelectAuthListItemSubtitleClass!}">
                                        <#list authenticator.transports.displayNameProperties as nameProperty>
                                            <span>${msg(nameProperty)}</span><#if nameProperty?has_next><span>, </span></#if>
                                        </#list>
                                    </div>
                                </#if>
                                <div class="${properties.kcSelectAuthListItemSubtitleClass!}">
                                    ${msg('webauthn-createdAt-label')} ${authenticator.createdAt}
                                </div>
                            </li>
                        </#list>
                    </ul>
                </#if>
            </#if>

            <p>${msg("fuguWebAuthnLoginHelp")}</p>
            <@buttons.actionGroup horizontal=true>
                <@buttons.button id="authenticatePlatform" label="fuguWebAuthnRegisterPlatform" autofocus="autofocus"/>
                <@buttons.button id="authenticateCrossPlatform" label="fuguWebAuthnRegisterCrossPlatform" type="secondary"/>
            </@buttons.actionGroup>
        </div>
        <script type="module">
            <#outputformat "JavaScript">
            import { authenticateByWebAuthn } from "${url.resourcesPath}/js/webauthnAuthenticate.js";
            const input = {
                isUserIdentified : ${isUserIdentified},
                challenge : ${challenge?c},
                userVerification : ${userVerification?c},
                rpId : ${rpId?c},
                createTimeout : ${createTimeout?c},
                errmsg : ${msg("webauthn-unsupported-browser-text")?c}
            };
            document.getElementById('authenticatePlatform').addEventListener("click", function() {
                authenticateByWebAuthn({ ...input, hints: ['client-device'] });
            }, { once: true });
            document.getElementById('authenticateCrossPlatform').addEventListener("click", function() {
                authenticateByWebAuthn({ ...input, hints: ['hybrid', 'security-key'] });
            }, { once: true });
            </#outputformat>
        </script>
    <#elseif section = "info">
        <#if realm.registrationAllowed && !registrationDisabled??>
            <div id="kc-registration">
                <span>${msg("noAccount")} <a href="${url.registrationUrl}">${msg("doRegister")}</a></span>
            </div>
        </#if>
    </#if>
</@layout.registrationLayout>
