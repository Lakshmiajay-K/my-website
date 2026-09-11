from datetime import datetime


def generate_forensic_report(
    email_data,
    threat_analysis,
    geo_analysis
):

    sender = email_data.get(
        "from",
        []
    )

    sender_address = (
        sender[0][1]
        if sender
        else None
    )


    report = {

        "report_type":
            "Email Threat Forensic Investigation",

        "generated_at":
            datetime.utcnow().isoformat() + "Z",

        "case_summary": {

            "classification":
                threat_analysis.get(
                    "classification"
                ),

            "threat_score":
                threat_analysis.get(
                    "threat_score"
                ),

            "confidence":
                threat_analysis.get(
                    "confidence"
                )

        },


        "email_identity": {

            "sender":
                sender_address,

            "recipient":
                email_data.get(
                    "to"
                ),

            "subject":
                email_data.get(
                    "subject"
                ),

            "date":
                email_data.get(
                    "date"
                ),

            "reply_to":
                email_data.get(
                    "reply_to"
                )

        },


        "authentication": 
            threat_analysis.get(
                "authentication_analysis"
            ),


        "sender_intelligence":
            threat_analysis.get(
                "sender_analysis"
            ),


        "impersonation_intelligence":
            threat_analysis.get(
                "impersonation_analysis"
            ),


        "url_intelligence":
            threat_analysis.get(
                "url_analysis"
            ),


        "domain_intelligence":
            threat_analysis.get(
                "domain_analysis"
            ),


        "correlation_intelligence":
            threat_analysis.get(
                "correlation_analysis"
            ),


        "content_intelligence":
            threat_analysis.get(
                "content_analysis"
            ),


        "attachment_intelligence":
            threat_analysis.get(
                "attachment_analysis"
            ),


        "ip_intelligence":
            threat_analysis.get(
                "ip_analysis"
            ),


        "geolocation":
            geo_analysis,


        "risk_breakdown":
            threat_analysis.get(
                "risk_breakdown"
            ),


        "threat_indicators":
            threat_analysis.get(
                "indicators"
            ),


        "forensic_timeline":
            threat_analysis.get(
                "forensic_timeline"
            )

    }


    return report