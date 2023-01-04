using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Udap.Common.Models;
using Udap.Idp.Admin.Services.DataBase;
using Udap.Server.Mappers;

[Route("api/[controller]")]
[ApiController]
public class RootCertificateController : ControllerBase
{
    IRootCertificateService _rootCertificateService;
    ILogger<RootCertificateController> _logger;

    public RootCertificateController(IRootCertificateService rootCertificateService, ILogger<RootCertificateController> logger)
    {
        _rootCertificateService = rootCertificateService;
        _logger = logger;
    }

    // GET: api/<RootCertificateController>
    [HttpGet]
    public async Task<ActionResult<IEnumerable<RootCertificate>>> GetAsync(CancellationToken token)
    {
        var entitities = await _rootCertificateService.Get(token);

        if (!entitities.Any())
        {
            return NotFound();
        }

        var communities = entitities.Select(e => e.ToModel());

        return Ok(communities);
    }

    // GET api/<RootCertificateController>/5
    [HttpGet("{id}")]
    public async Task<ActionResult<RootCertificate>> Get(int id, CancellationToken token)
    {
        var entity = await _rootCertificateService.Get(id, token);

        if (entity == null)
        {
            return NotFound();
        }
        var rootCertificate = entity.ToModel();

        return Ok(rootCertificate);
    }

    // POST api/<RootCertificateController>
    [HttpPost]
    public async Task<ActionResult<RootCertificate>> Post([FromBody] RootCertificate value, CancellationToken token)
    {
        try
        {
            var result = await _rootCertificateService.Add(value.ToEntity(), token).ConfigureAwait(false);

            return Created(result.Id.ToString(), result.ToModel());
        }
        catch (DbUpdateException ex)
        {
            _logger.LogError(ex, "Error calling {0}", nameof(Post));
            
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error calling {0}", nameof(Post));
            throw;
        }
    }

    // PUT api/<RootCertificateController>/5
    [HttpPut("{id}")]
    public async Task<ActionResult> Put(int id, [FromBody] RootCertificate value, CancellationToken token)
    {
        try
        {
            await _rootCertificateService.Update(value.ToEntity(), token).ConfigureAwait(false);

            return NoContent(); // https://www.rfc-editor.org/rfc/rfc9110.html#name-204-no-content
                                // Although... https://blog.ploeh.dk/2013/04/30/rest-lesson-learned-avoid-204-responses/
        }
        catch (DbUpdateException ex)
        {
            _logger.LogError(ex, "Error calling {0}", nameof(Put));

            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error calling {0}", nameof(Put));
            throw;
        }
    }

    // DELETE api/<RootCertificateController>/5
    [HttpDelete("{id}")]
    public async Task<ActionResult<bool>> Delete(int id, CancellationToken token)
    {
        var response = await _rootCertificateService.Delete(id, token);

        if (response)
        {
            return Ok();
        }

        return NotFound();
    }
}