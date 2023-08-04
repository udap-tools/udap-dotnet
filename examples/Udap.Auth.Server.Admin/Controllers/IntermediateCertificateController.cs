#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Udap.Auth.Server.Admin.Services.DataBase;
using Udap.Common.Models;
using Udap.Server.Mappers;

namespace Udap.Auth.Server.Admin.Controllers;

[Route("api/[controller]")]
[ApiController]
public class IntermediateCertificateController : ControllerBase
{
    IIntermediateCertificateService _intermediateCertificateService;
    ILogger<IntermediateCertificateController> _logger;

    public IntermediateCertificateController(IIntermediateCertificateService intermediateCertificateService, ILogger<IntermediateCertificateController> logger)
    {
        _intermediateCertificateService = intermediateCertificateService;
        _logger = logger;
    }

    // GET: api/<IntermediateCertificateController>
    [HttpGet]
    public async Task<ActionResult<IEnumerable<Intermediate>>> GetAsync(CancellationToken token)
    {
        var entitities = await _intermediateCertificateService.Get(token);

        if (!entitities.Any())
        {
            return NotFound();
        }

        var communities = entitities.Select(e => e.ToModel());

        return Ok(communities);
    }

    // GET api/<IntermediateCertificateController>/5
    [HttpGet("{id}")]
    public async Task<ActionResult<Intermediate>> Get(int id, CancellationToken token)
    {
        var entity = await _intermediateCertificateService.Get(id, token);

        if (entity == null)
        {
            return NotFound();
        }
        var intermediateCertificate = entity.ToModel();

        return Ok(intermediateCertificate);
    }

    // POST api/<IntermediateCertificateController>
    [HttpPost]
    public async Task<ActionResult<Intermediate>> Post([FromBody] Intermediate value, CancellationToken token)
    {
        try
        {
            var result = await _intermediateCertificateService.Add(value.ToEntity(), token).ConfigureAwait(false);

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

    // PUT api/<IntermediateCertificateController>/5
    [HttpPut("{id}")]
    public async Task<ActionResult> Put(int id, [FromBody] Intermediate value, CancellationToken token)
    {
        try
        {
            await _intermediateCertificateService.Update(value.ToEntity(), token).ConfigureAwait(false);

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

    // DELETE api/<IntermediateCertificateController>/5
    [HttpDelete("{id}")]
    public async Task<ActionResult<bool>> Delete(int id, CancellationToken token)
    {
        var response = await _intermediateCertificateService.Delete(id, token);

        if (response)
        {
            return Ok();
        }

        return NotFound();
    }
}