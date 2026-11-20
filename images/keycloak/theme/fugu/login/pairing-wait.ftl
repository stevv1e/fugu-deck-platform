<#import "template.ftl" as layout>

<@layout.registrationLayout; section>
    <#if section = "title">title
    <#elseif section = "header">Подтверждение входа на ПК
    <#elseif section = "form">
        <#if pairInvalid??>
            <p>Pairing недействителен или истёк. Вернитесь в приложение и создайте новый код.</p>
        <#else>
            <p>На телефоне откройте «Устройства», введите код с экрана ПК и подтвердите вход.</p>
            <p>Страница продолжит вход автоматически.</p>
            <script>setTimeout(function() { window.location.reload(); }, 2000);</script>
        </#if>
    </#if>
</@layout.registrationLayout>
