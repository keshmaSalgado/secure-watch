using FluentValidation;
using SecureWatch.Application.DTOs;

namespace SecureWatch.Application.Validators;

public class CreateSecurityEventValidator : AbstractValidator<CreateSecurityEventDto>
{
    public CreateSecurityEventValidator()
    {
        RuleFor(x => x.EventType)
            .NotEmpty().WithMessage("Event type is required.")
            .MaximumLength(100);

        RuleFor(x => x.SourceIp)
            .NotEmpty().WithMessage("Source IP address is required.")
            .MaximumLength(45);

        RuleFor(x => x.Description)
            .NotEmpty().WithMessage("Description is required.")
            .MaximumLength(1000);
    }
}

public class CreateIncidentValidator : AbstractValidator<CreateIncidentDto>
{
    public CreateIncidentValidator()
    {
        RuleFor(x => x.Title)
            .NotEmpty().WithMessage("Incident title is required.")
            .MaximumLength(200);

        RuleFor(x => x.Description)
            .NotEmpty().WithMessage("Description is required.")
            .MaximumLength(2000);

        RuleFor(x => x.RiskScore)
            .InclusiveBetween(0, 100).WithMessage("Risk score must be between 0 and 100.");
    }
}

public class AddIncidentNoteValidator : AbstractValidator<AddIncidentNoteDto>
{
    public AddIncidentNoteValidator()
    {
        RuleFor(x => x.NoteText)
            .NotEmpty().WithMessage("Note text cannot be empty.")
            .MaximumLength(3000);
    }
}

public class ResolveIncidentValidator : AbstractValidator<ResolveIncidentDto>
{
    public ResolveIncidentValidator()
    {
        RuleFor(x => x.ResolutionSummary)
            .NotEmpty().WithMessage("Resolution summary is required.")
            .MaximumLength(2000);
    }
}

public class UpdateSecurityRuleValidator : AbstractValidator<UpdateSecurityRuleDto>
{
    public UpdateSecurityRuleValidator()
    {
        RuleFor(x => x.Name)
            .NotEmpty().WithMessage("Rule name is required.")
            .MaximumLength(150);

        RuleFor(x => x.TimeWindowSeconds)
            .GreaterThan(0).WithMessage("Time window must be greater than zero.");

        RuleFor(x => x.ThresholdCount)
            .GreaterThan(0).WithMessage("Threshold count must be greater than zero.");

        RuleFor(x => x.BaseRiskScore)
            .InclusiveBetween(0, 100).WithMessage("Base risk score must be between 0 and 100.");
    }
}

